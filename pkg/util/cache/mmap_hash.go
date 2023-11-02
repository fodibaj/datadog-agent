package cache

import (
	"errors"
	"fmt"
	"golang.org/x/exp/slices"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"hash/maphash"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// hashPage is a 4k page of memory.  After two bookkeeping ints,
// it has an array of index entries, followed by the strings themselves.
// The index entries grow from the start of the 4k page to the end,
// and the strings grow from the end of the 4k page to the start.  The
// bookkeeping entries make sure they don't collide.
const hashPageSize = 4096
const numEntries = (hashPageSize - 8) / 8
const callStackDepth = 8

// MaxValueSize is the largest possible value we can store.  Start with the page size and take off 16:
// 8 (4+2+2) for a single hashEntry, and 8 for the two int32s on the top of hashPage
const MaxValueSize = hashPageSize - 16

// MaxProbes is the maximum number of probes going into the hash table.
const MaxProbes = 8

const maxFailedPointers = 2000000
const maxFailedPointersToPrint = 50

// containerSummaryPattern will help abbreviate the name of the container.
var containerSummaryPattern = regexp.MustCompile("^container_id://[0-9a-f]{60}([0-9a-f]{4})")

type hashEntry struct {
	hashCode       uint32
	offset, length uint16
}

type hashPage struct {
	indexEntries, stringData int32
	// This array isn't actually this long.  It's 'indexEntries' long
	// and the tail is getting overwritten with strings.  Adding a string grows
	// in two directions simultaneously: the entry is added to the front
	// of the page, and the string itself is prepended to the end.
	// The offset field of each hashEntry object is relative to the
	// address of the hashPage.
	entries [numEntries]hashEntry
}

func (hp *hashPage) insertAtIndex(index, hashcode int, key []byte) bool {
	const entSize = int32(unsafe.Sizeof(hp.entries[0]))
	remaining := hashPageSize - (hp.indexEntries*entSize + hp.stringData)
	if remaining < (entSize + int32(len(key))) {
		return false
	}
	copy(hp.entries[index+1:hp.indexEntries+1], hp.entries[index:hp.indexEntries])
	offset := hashPageSize - int(hp.stringData) - len(key)
	stringBuf := unsafe.Slice((*byte)(unsafe.Pointer(hp)), hashPageSize)
	copy(stringBuf[offset:offset+len(key)], key)
	hp.entries[index].hashCode = uint32(hashcode)
	hp.entries[index].length = uint16(len(key))
	hp.entries[index].offset = uint16(offset)
	hp.indexEntries += 1
	hp.stringData += int32(len(key))
	return true
}

// lookupOrInsert returns the allocated string and true, if it allocated. It
// returns empty string if it didn't fit here, and false. That means we treat
// this as a hash collision and find another page to look into (or insert)
func (hp *hashPage) lookupOrInsert(hcode uint64, key []byte) (string, bool) {
	maskCode := func(hc uint64) int {
		return int(hc & 0xFFFFFFFF)
	}
	maskedHCode := maskCode(hcode)
	index, found := slices.BinarySearchFunc(hp.entries[:hp.indexEntries], hcode,
		func(ent hashEntry, hc uint64) int {
			return int(ent.hashCode) - maskCode(hc)
		})
	if !found {
		if !hp.insertAtIndex(index, maskedHCode, key) {
			return "", false
		}
	}
	return unsafe.String((*byte)(unsafe.Add(unsafe.Pointer(hp), hp.entries[index].offset)),
		int(hp.entries[index].length)), !found
}

type mmapHash struct {
	name           string
	fd             fs.File
	used, capacity int64 // Bytes used and capacity for strings in the
	seeds          []maphash.Seed
	seedHist       []uint64 // Histograms of lookups that succeeded with the Nth seed.
	pages          []hashPage
	mapping        []byte // This is virtual address space, not memory used.
	closeOnRelease bool
	// value-length statistics, Welford's online variance algorithm
	valueCount uint64
	valueMean  float64
	valueM2    float64
	lock       sync.Mutex
}

type failedPointer struct {
	origin string
	count  int
}

// mmapAllRecord holds every mmapHash created.  This isn't for permanent use,
// just debugging and validation.
type mmapAllRecord struct {
	// When we actually delete, make this nil.
	hashes   []*mmapHash
	origins  map[string]int
	pointers map[uintptr]failedPointer
	lock     sync.Mutex
}

var allMmaps = mmapAllRecord{
	hashes:   make([]*mmapHash, 0, 1),
	origins:  make(map[string]int),
	pointers: make(map[uintptr]failedPointer),
}

func normalizeOrigin(origin string) string {
	result := strings.Builder{}
	for _, c := range origin {
		switch c {
		case '/':
			fallthrough
		case ':':
			fallthrough
		case ' ':
			result.WriteRune('_')
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

func newMmapHash(origin string, fileSize int64, prefixPath string, closeOnRelease bool) (*mmapHash, error) {
	if fileSize < hashPageSize {
		return nil, errors.New("file size too small")
	}
	file, err := os.OpenFile(filepath.Join(prefixPath, fmt.Sprintf("%s-%d.dat", normalizeOrigin(origin), fileSize)),
		os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil, err
	}

	// Delete the file so that only our open FD keeps the inode alive.
	defer func(name string) {
		_ = os.Remove(name)
	}(file.Name())

	// Create the file, make a hole in it, mmap the hole.
	if _, err = syscall.Seek(int(file.Fd()), int64(fileSize-1), io.SeekStart); err != nil {
		return nil, err
	}
	// The hole requires a real byte after it to materialize.
	if _, err = file.Write(make([]byte, 1)); err != nil {
		return nil, err
	}

	mappedAddresses, err := syscall.Mmap(int(file.Fd()), 0, int(fileSize), syscall.PROT_WRITE|syscall.PROT_READ,
		syscall.MAP_SHARED|syscall.MAP_FILE)
	if err != nil {
		return nil, err
	}
	seeds := make([]maphash.Seed, 0, MaxProbes)
	for i := 0; i < MaxProbes; i++ {
		seeds = append(seeds, maphash.MakeSeed())
	}

	h := &mmapHash{
		name:           origin,
		fd:             file,
		used:           0,
		capacity:       fileSize,
		mapping:        mappedAddresses,
		pages:          unsafe.Slice((*hashPage)(unsafe.Pointer(&mappedAddresses[0])), fileSize/hashPageSize),
		seeds:          seeds,
		seedHist:       make([]uint64, len(seeds)),
		closeOnRelease: closeOnRelease,
	}

	allMmaps.lock.Lock()
	defer allMmaps.lock.Unlock()
	allMmaps.hashes = append(allMmaps.hashes, h)

	return h, nil
}

// lookupOrInsert returns a pre-existing or newly created string with the value of key.  It also
// returns a bool indicating whether implementation is full.  If you get an empty string and a true,
// you would be able to allocate this string on some other instance that isn't full.  If you get an
// empty string and a false, the implementation doesn't support this string.  Go ahead and
// heap-allocate the string, then.
func (table *mmapHash) lookupOrInsert(key []byte) (string, bool) {
	keyLen := len(key)
	if keyLen > MaxValueSize {
		// We don't support long strings, punt.
		return "", false
	}

	if table.mapping == nil {
		// We don't return strings after finalization.
		_ = log.Errorf("Attempted to use mmap hash after release!")

		// This will punt the error upwards, which will then allocate somewhere else.
		return "", false
	}
	for n, seed := range table.seeds {
		hash := maphash.Bytes(seed, key)
		page := &table.pages[hash%uint64(len(table.pages))]
		if result, allocated := page.lookupOrInsert(hash, key); result != "" {
			if allocated {
				// Online mean & variance calculation:
				// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
				keyLenF := float64(keyLen)
				table.used += int64(keyLen)
				table.valueCount += 1
				delta := keyLenF - table.valueMean
				table.valueMean += delta / float64(table.valueCount)
				delta2 := keyLenF - table.valueMean
				table.valueM2 += delta * delta2
			}
			table.seedHist[n] += 1
			return result, false
		}
	}
	return "", true
}

func (table *mmapHash) sizes() (int64, int64) {
	return table.used, table.capacity
}

// stats returns the mean and variance for the lengths of keys inserted into
// this mmapHash. When these values aren't defined, you get NaN back.
func (table *mmapHash) stats() (float64, float64) {
	if table.valueCount < 1 {
		return math.NaN(), math.NaN()
	} else if table.valueCount < 2 {
		return table.valueMean, math.NaN()
	} else {
		return table.valueMean, table.valueM2 / float64(table.valueCount)
	}
}

func (table *mmapHash) Name() string {
	if len(table.name) == 0 {
		return "<empty>"
	} else if table.name[0] == '!' {
		return table.name
	} else {
		return containerSummaryPattern.ReplaceAllString(table.name, "container-$1")
	}
}

func (table *mmapHash) finalize() {
	table.lock.Lock()
	defer table.lock.Unlock()
	if table.pages == nil {
		_ = log.Warnf("finalize(%p): Already dead.", table)
	}

	if strings.HasSuffix(table.name, "parseMetricSample_name") || strings.Contains(table.name, "!Timesampler.Name") {
		log.Infof("Finalizing a segment that often causes issues.")
	}

	table.pages = nil
	address := unsafe.SliceData(table.mapping)
	_ = log.Warnf(fmt.Sprintf("finalize(%s): Invalidating address %p-%p.",
		table.Name(), address, unsafe.Add(unsafe.Pointer(address), len(table.mapping))))
	// Make the segment read-only, worry about actual deletion after we have
	// better debugging around page faults.
	var err error
	if table.closeOnRelease {
		err = syscall.Munmap(table.mapping)
		if err != nil {
			_ = log.Errorf("Failed munmap(): ", err)
		}
		err = table.fd.Close()
		if err != nil {
			_ = log.Errorf("Failed mapping file close(): ", err)
		}
		table.fd = nil
	} else {
		// Don't close the mapping, just mark it read-only.  This leaks to disk and address space, but it's
		// still better than using up heap.  It also lets us track down reference leaks to this address
		// space without crashing.
		err = syscall.Mprotect(table.mapping, syscall.PROT_READ)
		if err != nil {
			_ = log.Errorf("Failed mprotect(): ", err)
		}
	}
}

func (table *mmapHash) finalized() bool {
	return table.pages == nil
}

func (table *mmapHash) accessible() bool {
	return table.fd != nil
}

// isMapped returns (index, active, safe) for the string s.  If the address is mapped,
// index >= 0 (else -1).  And if that mapping is still active, we get active=true.  If
// the address is still mapped in the process address space (active or not), we get safe=true.
// Caller must hold lock to all_maps.lock.  If index < 0, the other two return values are
// irrelevant.
func isMapped(s string) (int, bool, bool) {
	// TODO: make isMapped lock-free.
	addr := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	var constP *byte = nil
	for n, t := range allMmaps.hashes {
		t.lock.Lock()
		mapAddr := uintptr(unsafe.Pointer(unsafe.SliceData(t.mapping)))
		if mapAddr <= addr && addr <= (mapAddr+unsafe.Sizeof(constP)*uintptr(len(t.mapping))) {
			// Found it.
			active := !t.finalized()
			safe := t.accessible()
			if !active {
				if entry, ok := allMmaps.pointers[mapAddr]; !ok {
					if len(allMmaps.pointers) < maxFailedPointers {
						allMmaps.pointers[mapAddr] = failedPointer{
							origin: t.Name(),
							count:  1,
						}
					}
				} else {
					entry.count += 1
					allMmaps.pointers[mapAddr] = entry
				}
			}
			t.lock.Unlock()
			return n, active, safe
		}
		t.lock.Unlock()
	}
	// address isn't part of our memory mapping, so it's safe to return.
	return -1, false, true
}

// logFailedCheck returns a safe value for 'tag'.  Using the 'safe' value from isMapped,
// logFailedCheck will log a failed call to isMapped and
func logFailedCheck(index int, safe bool, callsite, tag string) string {
	location := fmt.Sprintf("<%s>", allMmaps.hashes[index].Name())
	for i := 0; i < callStackDepth; i++ {
		// skip over logFailedCheck and the in-package call site, just the ones above.
		_, file, line, _ := runtime.Caller(2 + i)
		location = fmt.Sprintf("%s\t[%s:%d]", location,
			strings.Replace(file, "/go/src/github.com/DataDog/datadog-agent/pkg", "PKG", 1), line)
	}
	if _, found := allMmaps.origins[location]; !found {
		if safe {
			_ = log.Errorf("mmap_hash.%v: Found tag (%s) from dead region, called from %v", callsite, tag, location)
		} else {
			_ = log.Errorf("mmap_hash.%v: Found tag (INACCESSIBLE) from dead region, called from %v", callsite, location)
		}
	}
	allMmaps.origins[location] += 1
	if safe {
		return tag
	} else {
		return location
	}
}

func Check(tag string) bool {
	allMmaps.lock.Lock()
	defer allMmaps.lock.Unlock()

	index, active, safe := isMapped(tag)
	if index >= 0 && !active {
		logFailedCheck(index, safe, "Check", tag)
	}
	return safe
}

func CheckDefault(tag string) string {
	allMmaps.lock.Lock()
	defer allMmaps.lock.Unlock()
	index, active, safe := isMapped(tag)
	if index >= 0 && !active {
		return logFailedCheck(index, safe, "CheckDefault", tag)
	} else {
		return tag
	}
}

// Report the active and dead mappings, their lookup depths, and all the failed lookup checks.
func Report() {
	allMmaps.lock.Lock()
	defer allMmaps.lock.Unlock()
	p := message.NewPrinter(language.English)
	nrHashes := len(allMmaps.hashes)
	type originData struct {
		name                                 string
		totalValues                          uint64
		totalActiveAllocated, totalAllocated int64
	}

	mapData := make(map[string]originData)
	for n, t := range allMmaps.hashes {
		var status string
		name := t.Name()
		data := mapData[name]
		data.name = name
		data.totalValues += t.valueCount
		data.totalAllocated += t.capacity
		if t.finalized() {
			status = "INACTIVE"
		} else {
			data.totalActiveAllocated += t.capacity
			status = "ACTIVE"
		}
		mapData[name] = data

		mean, variance := t.stats()
		log.Debug(p.Sprintf("> %d/%d: %8s Origin=\"%s\" mmap range starting at %p: %v bytes."+
			" Used: %11d, capacity: %11d.  Utilization: %4.1f%%. Mean len: %4.2f, "+
			"Stddev len: %4.2f. Lookup depth: %10d %6d %5d %5d %3d %2d %2d %d", n+1, nrHashes, status,
			t.Name(), unsafe.Pointer(unsafe.SliceData(t.mapping)), len(t.mapping),
			t.used, t.capacity, 100.0*float64(t.used)/float64(t.capacity), mean, math.Sqrt(variance),
			t.seedHist[0], t.seedHist[1], t.seedHist[2], t.seedHist[3],
			t.seedHist[4], t.seedHist[5], t.seedHist[6], t.seedHist[7]))
	}

	for k, v := range mapData {
		log.Info(p.Sprintf("* %40s: Total Values: %d, Active Bytes Allocated: %d, Total Bytes Allocated: %d",
			k, v.totalValues, v.totalActiveAllocated, v.totalAllocated))
	}

	nrChecks := len(allMmaps.origins)
	count := 1
	totalFailedChecks := 0
	for k, v := range allMmaps.origins {
		log.Info(p.Sprintf("- %3d/%d %12d/ failed checks: %s", count, nrChecks, v, k))
		totalFailedChecks += v
		count += 1
	}
	log.Info(p.Sprintf("Failed Checks Total %d on %d different locations", totalFailedChecks, len(allMmaps.origins)))

	if len(allMmaps.pointers) < maxFailedPointersToPrint {
		for ptr, entry := range allMmaps.pointers {
			log.Info(p.Sprintf("Address %p in %s: %d hits", unsafe.Pointer(ptr), entry.origin, entry.count))
		}
	} else {
		log.Info(p.Sprintf("Too many (%d) pointers saved.", len(allMmaps.pointers)))
	}
}
