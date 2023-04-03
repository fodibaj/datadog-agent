// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build trivy
// +build trivy

package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/hashicorp/golang-lru/simplelru"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta/telemetry"
)

// telemetryTick is the frequency at which the cache usage metrics are collected.
var telemetryTick = 1 * time.Minute

// CacheProvider describe a function that provides a type implementing the trivy cache interface
type CacheProvider func() (cache.Cache, error)

// NewBoltCache is a CacheProvider. It returns a BoltDB cache provided by Trivy.
func NewBoltCache(cacheDir string) (cache.Cache, error) {
	if cacheDir == "" {
		cacheDir = utils.DefaultCacheDir()
	}

	return cache.NewFSCache(cacheDir)
}

// NewCustomBoltCache is a CacheProvider. It returns a custom implementation of a BoltDB cache using an LRU algorithm with a
// maximum number of cache entries, maximum disk size and garbage collection of unused images.
func NewCustomBoltCache(cacheDir string, maxCacheEntries int, maxDiskSize int, gcInterval time.Duration) (cache.Cache, error) {
	if cacheDir == "" {
		cacheDir = utils.DefaultCacheDir()
	}
	db, err := NewBoltDB(cacheDir)
	if err != nil {
		return nil, err
	}
	cache, err := NewPersistentCache(
		maxCacheEntries,
		maxDiskSize,
		db,
		NewMaintainer(gcInterval, telemetryTick),
	)
	if err != nil {
		return nil, err
	}
	return &TrivyCache{
		Cache: cache,
	}, nil
}

// Cache describes an interface for a key-value cache.
type Cache interface {
	// Clear removes all entries from the cache and closes it.
	Clear() error
	// Close closes the cache.
	Close() error
	// Contains returns true if the given key exists in the cache.
	Contains(key string) bool
	// Remove deletes the entries associated with the given keys from the cache.
	Remove(keys []string) error
	// Set inserts or updates an entry in the cache with the given key-value pair.
	Set(key string, value []byte) error
	// Get returns the value associated with the given key. It returns an error if the key was not found.
	Get(key string) ([]byte, error)
}

// collectTelemetry collects the database's size
func (cache *PersistentCache) collectTelemetry() {
	diskSize, err := cache.db.Size()
	if err != nil {
		log.Errorf("could not collect telemetry: %v", err)
	}
	telemetry.SBOMCacheDiskSize.Set(float64(diskSize))
}

// TrivyCache holds a generic Cache and implements cache.Cache from Trivy.
type TrivyCache struct {
	Cache Cache
}

// CachedObject describe an object that can be stored with TrivyCache
type CachedObject interface {
	types.ArtifactInfo | types.BlobInfo
}

// NewTrivyCache creates a new TrivyCache instance with the provided Cache.
func NewTrivyCache(cache Cache) *TrivyCache {
	return &TrivyCache{
		Cache: cache,
	}
}

// trivyCachePut stores the provided cachedObject in the TrivyCache with the provided key.
func trivyCachePut[T CachedObject](cache *TrivyCache, id string, info T) error {
	objectBytes, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error converting object with ID %q to JSON: %w", id, err)
	}
	return cache.Cache.Set(id, objectBytes)
}

// trivyCacheGet retrieves the object stored with the provided key.
func trivyCacheGet[T CachedObject](cache *TrivyCache, id string) (T, error) {
	rawValue, err := cache.Cache.Get(id)
	var empty T

	if err != nil {
		return empty, fmt.Errorf("error getting object with ID %q from Badger cache: %w", id, err)
	}

	var res T
	if err := json.Unmarshal(rawValue, &res); err != nil {
		return empty, fmt.Errorf("JSON unmarshal error: %w", err)
	}

	return res, nil
}

// Implements cache.Cache#MissingBlobs
func (c *TrivyCache) MissingBlobs(artifactID string, blobIDs []string) (bool, []string, error) {
	var missingBlobIDs []string
	for _, blobID := range blobIDs {
		if ok := c.Cache.Contains(blobID); !ok {
			missingBlobIDs = append(missingBlobIDs, blobID)
		}
	}
	return !c.Cache.Contains(artifactID), missingBlobIDs, nil
}

// Implements cache.Cache#PutArtifact
func (c *TrivyCache) PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) error {
	return trivyCachePut(c, artifactID, artifactInfo)
}

// Implements cache.Cache#PutBlob
func (c *TrivyCache) PutBlob(blobID string, blobInfo types.BlobInfo) error {
	return trivyCachePut(c, blobID, blobInfo)
}

// Implements cache.Cache#DeleteBlobs
func (c *TrivyCache) DeleteBlobs(blobIDs []string) error {
	return c.Cache.Remove(blobIDs)
}

// Implements cache.Cache#Clear
func (c *TrivyCache) Clear() error {
	return c.Cache.Clear()
}

// Implements cache.Cache#Close
func (c *TrivyCache) Close() error {
	return c.Cache.Close()
}

// Implements cache.Cache#GetArtifact
func (c *TrivyCache) GetArtifact(id string) (types.ArtifactInfo, error) {
	return trivyCacheGet[types.ArtifactInfo](c, id)
}

// Implements cache.Cache#GetBlob
func (c *TrivyCache) GetBlob(id string) (types.BlobInfo, error) {
	return trivyCacheGet[types.BlobInfo](c, id)
}

// Maintainer periodically removes unused entries from the cache and collects telemetry.
// It holds a ticket for garbage collection and another for collecting telemetry.
type Maintainer struct {
	gcTicker        *time.Ticker
	telemetryTicker *time.Ticker
}

// Clean lists images from the workloadmeta, gets the list of currently used artifactIDs and blobIDs and
// removes all the others from the cache.
func (c *Maintainer) Clean(cache *PersistentCache) {
	toKeep := make(map[string]struct{})
	for _, imageMetadata := range workloadmeta.GetGlobalStore().ListImages() {
		sbom := imageMetadata.SBOM
		toKeep[sbom.ArtifactID] = struct{}{}
		for _, blobID := range sbom.BlobIDs {
			toKeep[blobID] = struct{}{}
		}
	}
	var toRemove []string
	for _, key := range cache.Keys() {
		if _, ok := toKeep[key]; !ok {
			toRemove = append(toRemove, key)
		}
	}

	err := cache.Remove(toRemove)
	if err != nil {
		// will always be triggered if the database is closed
		log.Errorf("error cleaning the database: %v", err)
	}
}

// Maintain periodically cleans the cache and collects telemetry
func (m *Maintainer) Maintain(cache *PersistentCache) {
	for {
		select {
		case <-m.telemetryTicker.C:
			cache.collectTelemetry()
		case <-m.gcTicker.C:
			m.Clean(cache)
		}
	}
}

// NewMaintainer creates a new instance of Maintainer and returns a pointer to it.
func NewMaintainer(gcTick time.Duration, telemetryTick time.Duration) *Maintainer {
	return &Maintainer{
		gcTicker:        time.NewTicker(gcTick),
		telemetryTicker: time.NewTicker(telemetryTick),
	}
}

// PersistentCache is a cache that uses a persistent database for storage.
type PersistentCache struct {
	ctx                          context.Context
	lruCache                     *simplelru.LRU
	db                           PersistentDB
	mutex                        sync.RWMutex
	currentCachedObjectTotalSize int
	maximumCachedObjectSize      int
	lastEvicted                  string
}

// NewPersistentCache creates a new instance of PersistentCache and returns a pointer to it.
func NewPersistentCache(
	maxCacheSize int,
	maxCachedObjectSize int,
	localDB PersistentDB,
	maintainer *Maintainer,
) (*PersistentCache, error) {

	persistentCache := &PersistentCache{
		db:                           localDB,
		currentCachedObjectTotalSize: 0,
		maximumCachedObjectSize:      maxCachedObjectSize,
	}

	lruCache, err := simplelru.NewLRU(maxCacheSize, func(key interface{}, _ interface{}) {
		persistentCache.lastEvicted = key.(string)
		telemetry.SBOMCacheEvicts.Inc()
	})
	if err != nil {
		return nil, err
	}
	persistentCache.lruCache = lruCache

	var evicted []string
	if err = localDB.ForEach(func(key string, value []byte) error {
		if ok := lruCache.Add(key, struct{}{}); ok {
			evicted = append(evicted, persistentCache.lastEvicted)
		}
		persistentCache.addCurrentCachedObjectTotalSize(len(value))
		return nil
	}); err != nil {
		return nil, err
	}

	err = persistentCache.Remove(evicted)
	if err != nil {
		return nil, err
	}

	go maintainer.Maintain(persistentCache)

	return persistentCache, nil
}

// Contains implements Cache#Contains. It only performs an in-memory check.
func (c *PersistentCache) Contains(key string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.lruCache.Contains(key)
}

// Keys returns all the keys stored in the lru cache.
func (c *PersistentCache) Keys() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	keys := make([]string, c.lruCache.Len())
	for i, key := range c.lruCache.Keys() {
		keys[i] = key.(string)
	}
	return keys
}

// Len returns the number of items in the cache.
func (c *PersistentCache) Len() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.lruCache.Len()
}

// Clear implements Cache#Clear.
func (c *PersistentCache) Clear() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if err := c.db.Clear(); err != nil {
		return err
	}
	c.lruCache.Purge()
	c.currentCachedObjectTotalSize = 0
	telemetry.SBOMCachedObjectSize.Set(0)
	return nil
}

// removeOldest removes the least recently used item from the cache.
func (c *PersistentCache) removeOldest() error {
	key, _, ok := c.lruCache.RemoveOldest()
	if !ok {
		return fmt.Errorf("in-memory cache is empty")
	}

	evicted := 0
	if err := c.db.Delete([]string{key.(string)}, func(key string, value []byte) error {
		evicted += len(value)
		return nil
	}); err != nil {
		return err
	}

	c.subCurrentCachedObjectTotalSize(evicted)

	return nil
}

// RemoveOldest is a thread-safe version of removeOldest
func (c *PersistentCache) RemoveOldest() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.removeOldest()
}

// reduceSize reduces the size of the cache to the target size by evicting the oldest items.
func (c *PersistentCache) reduceSize(target int) error {
	if c.currentCachedObjectTotalSize <= target {
		return nil
	}

	prev := c.currentCachedObjectTotalSize
	for c.currentCachedObjectTotalSize > target {
		err := c.removeOldest()
		if err != nil {
			return err
		}
		if prev == c.currentCachedObjectTotalSize {
			// if c.currentCachedObjectTotalSize is not updated by removeOldest then an item is stored in the lrucache without being stored in the local storage
			return fmt.Errorf("cache and db are out of sync")
		}
	}
	return nil
}

// Close implements Cache#Close
func (c *PersistentCache) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.db.Close()
}

// set stores the key-value pair in the cache.
func (c *PersistentCache) set(key string, value []byte) error {
	if len(value) > c.maximumCachedObjectSize {
		return fmt.Errorf("value of [%s] is too big for the cache : %d", key, c.maximumCachedObjectSize)
	}

	if c.currentCachedObjectTotalSize+len(value) > c.maximumCachedObjectSize {
		if err := c.reduceSize(c.maximumCachedObjectSize - len(value)); err != nil {
			return err
		}
	}

	if evict := c.lruCache.Add(key, struct{}{}); evict {
		evictedSize := 0
		if err := c.db.Delete([]string{c.lastEvicted}, func(_ string, value []byte) error {
			evictedSize += len(value)
			return nil
		}); err != nil {
			c.lruCache.Remove(key)
			c.lruCache.Add(c.lastEvicted, struct{}{})
			return err
		}
		c.subCurrentCachedObjectTotalSize(evictedSize)
	}

	err := c.db.Store(key, value)
	if err != nil {
		c.lruCache.Remove(key)
		return err
	}

	c.addCurrentCachedObjectTotalSize(len(value))
	return nil
}

// Set implements Cache#Set. It is a thread-safe version of set.
func (c *PersistentCache) Set(key string, value []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.set(key, value)
}

// Get implements Cache#Get.
func (c *PersistentCache) Get(key string) ([]byte, error) {
	ok := c.Contains(key)
	if !ok {
		telemetry.SBOMCacheMisses.Inc()
		return nil, fmt.Errorf("key not found")
	}

	res, err := c.db.Get(key)
	if err != nil {
		_ = c.Remove([]string{key})
		return nil, err
	}
	telemetry.SBOMCacheHits.Inc()
	return res, nil
}

// remove removes an entry from the cache.
func (c *PersistentCache) remove(keys []string) error {
	removedSize := 0
	if err := c.db.Delete(keys, func(_ string, value []byte) error {
		removedSize += len(value)
		return nil
	}); err != nil {
		return err
	}

	for _, key := range keys {
		_ = c.lruCache.Remove(key)
	}

	c.subCurrentCachedObjectTotalSize(removedSize)
	return nil
}

// Remove implements Cache#Remove. It is a thread safe version of remove.
func (c *PersistentCache) Remove(keys []string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.remove(keys)
}

// GetCurrentCachedObjectTotalSize returns the current cached object total size.
func (c *PersistentCache) GetCurrentCachedObjectTotalSize() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.currentCachedObjectTotalSize
}

// addCurrentCachedObjectTotalSize adds val to the current cached object total size.
func (c *PersistentCache) addCurrentCachedObjectTotalSize(val int) {
	c.currentCachedObjectTotalSize += val
	telemetry.SBOMCachedObjectSize.Add(float64(val))
}

// subCurrentCachedObjectTotalSize substract val to the current cached object total size.
func (c *PersistentCache) subCurrentCachedObjectTotalSize(val int) {
	c.currentCachedObjectTotalSize -= val
	telemetry.SBOMCachedObjectSize.Sub(float64(val))
}
