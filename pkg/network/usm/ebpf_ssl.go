// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
	"github.com/davecgh/go-spew/spew"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/go/bininspect"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/network/usm/buildmode"
	"github.com/DataDog/datadog-agent/pkg/network/usm/sharedlibraries"
	"github.com/DataDog/datadog-agent/pkg/network/usm/utils"
	"github.com/DataDog/datadog-agent/pkg/util/common"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	sslReadExProbe              = "uprobe__SSL_read_ex"
	sslReadExRetprobe           = "uretprobe__SSL_read_ex"
	sslWriteExProbe             = "uprobe__SSL_write_ex"
	sslWriteExRetprobe          = "uretprobe__SSL_write_ex"
	ssDoHandshakeProbe          = "uprobe__SSL_do_handshake"
	ssDoHandshakeRetprobe       = "uretprobe__SSL_do_handshake"
	sslConnectProbe             = "uprobe__SSL_connect"
	sslConnectRetprobe          = "uretprobe__SSL_connect"
	sslSetBioProbe              = "uprobe__SSL_set_bio"
	sslSetFDProbe               = "uprobe__SSL_set_fd"
	sslReadProbe                = "uprobe__SSL_read"
	sslReadRetprobe             = "uretprobe__SSL_read"
	sslWriteProbe               = "uprobe__SSL_write"
	sslWriteRetprobe            = "uretprobe__SSL_write"
	sslShutdownProbe            = "uprobe__SSL_shutdown"
	bioNewSocketProbe           = "uprobe__BIO_new_socket"
	bioNewSocketRetprobe        = "uretprobe__BIO_new_socket"
	gnutlsHandshakeProbe        = "uprobe__gnutls_handshake"
	gnutlsHandshakeRetprobe     = "uretprobe__gnutls_handshake"
	gnutlsTransportSetInt2Probe = "uprobe__gnutls_transport_set_int2"
	gnutlsTransportSetPtrProbe  = "uprobe__gnutls_transport_set_ptr"
	gnutlsTransportSetPtr2Probe = "uprobe__gnutls_transport_set_ptr2"
	gnutlsRecordRecvProbe       = "uprobe__gnutls_record_recv"
	gnutlsRecordRecvRetprobe    = "uretprobe__gnutls_record_recv"
	gnutlsRecordSendProbe       = "uprobe__gnutls_record_send"
	gnutlsRecordSendRetprobe    = "uretprobe__gnutls_record_send"
	gnutlsByeProbe              = "uprobe__gnutls_bye"
	gnutlsDeinitProbe           = "uprobe__gnutls_deinit"
)

var openSSLProbes = []manager.ProbesSelector{
	&manager.BestEffort{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslReadExProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslReadExRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslWriteExProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslWriteExRetprobe,
				},
			},
		},
	},
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: ssDoHandshakeProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: ssDoHandshakeRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslConnectProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslConnectRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslSetBioProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslSetFDProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslReadProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslReadRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslWriteProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslWriteRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: sslShutdownProbe,
				},
			},
		},
	},
}

var cryptoProbes = []manager.ProbesSelector{
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: bioNewSocketProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: bioNewSocketRetprobe,
				},
			},
		},
	},
}

var gnuTLSProbes = []manager.ProbesSelector{
	&manager.AllOf{
		Selectors: []manager.ProbesSelector{
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsHandshakeProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsHandshakeRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsTransportSetInt2Probe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsTransportSetPtrProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsTransportSetPtr2Probe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsRecordRecvProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsRecordRecvRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsRecordSendProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsRecordSendRetprobe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsByeProbe,
				},
			},
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: gnutlsDeinitProbe,
				},
			},
		},
	},
}

const (
	sslSockByCtxMap = "ssl_sock_by_ctx"
)

var (
	buildKitProcessName = []byte("buildkitd")
)

// Template, will be modified during runtime.
// The constructor of SSLProgram requires more parameters than we provide in the general way, thus we need to have
// a dynamic initialization.
var opensslSpec = &protocols.ProtocolSpec{
	Maps: []*manager.Map{
		{
			Name: sslSockByCtxMap,
		},
		{
			Name: "ssl_read_args",
		},
		{
			Name: "ssl_read_ex_args",
		},
		{
			Name: "ssl_write_args",
		},
		{
			Name: "ssl_write_ex_args",
		},
		{
			Name: "bio_new_socket_args",
		},
		{
			Name: "fd_by_ssl_bio",
		},
		{
			Name: "ssl_ctx_by_pid_tgid",
		},
	},
	Probes: []*manager.Probe{
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslReadExProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslReadExRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslWriteExProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslWriteExRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: ssDoHandshakeProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: ssDoHandshakeRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslConnectProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslConnectRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslSetBioProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslSetFDProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslReadProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslReadRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslWriteProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslWriteRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: sslShutdownProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: bioNewSocketProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: bioNewSocketRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsHandshakeProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsHandshakeRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsTransportSetInt2Probe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsTransportSetPtrProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsTransportSetPtr2Probe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsRecordRecvProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsRecordRecvRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsRecordSendProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsRecordSendRetprobe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsByeProbe,
			},
		},
		{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				EBPFFuncName: gnutlsDeinitProbe,
			},
		},
	},
}

type sslProgram struct {
	cfg          *config.Config
	watcher      *sharedlibraries.Watcher
	istioMonitor *istioMonitor
}

func newSSLProgramProtocolFactory(m *manager.Manager, bpfTelemetry *errtelemetry.EBPFTelemetry) protocols.ProtocolFactory {
	return func(c *config.Config) (protocols.Protocol, error) {
		if (!c.EnableNativeTLSMonitoring || !http.TLSSupported(c)) && !c.EnableIstioMonitoring {
			return nil, nil
		}

		var (
			watcher *sharedlibraries.Watcher
			err     error
		)

		procRoot := kernel.ProcFSRoot()

		if c.EnableNativeTLSMonitoring && http.TLSSupported(c) {
			watcher, err = sharedlibraries.NewWatcher(c, bpfTelemetry,
				sharedlibraries.Rule{
					Re:           regexp.MustCompile(`libssl.so`),
					RegisterCB:   addHooks(m, procRoot, openSSLProbes),
					UnregisterCB: removeHooks(m, openSSLProbes),
				},
				sharedlibraries.Rule{
					Re:           regexp.MustCompile(`libcrypto.so`),
					RegisterCB:   addHooks(m, procRoot, cryptoProbes),
					UnregisterCB: removeHooks(m, cryptoProbes),
				},
				sharedlibraries.Rule{
					Re:           regexp.MustCompile(`libgnutls.so`),
					RegisterCB:   addHooks(m, procRoot, gnuTLSProbes),
					UnregisterCB: removeHooks(m, gnuTLSProbes),
				},
			)
			if err != nil {
				return nil, fmt.Errorf("error initializing shared library watcher: %s", err)
			}
		}

		return &sslProgram{
			cfg:          c,
			watcher:      watcher,
			istioMonitor: newIstioMonitor(c, m),
		}, nil
	}
}

func (o *sslProgram) Name() string {
	return "openssl"
}

func (o *sslProgram) ConfigureOptions(_ *manager.Manager, options *manager.Options) {
	options.MapSpecEditors[sslSockByCtxMap] = manager.MapSpecEditor{
		MaxEntries: o.cfg.MaxTrackedConnections,
		EditorFlag: manager.EditMaxEntries,
	}

	if options.MapEditors == nil {
		options.MapEditors = make(map[string]*ebpf.Map)
	}
}

func (o *sslProgram) PreStart(*manager.Manager) error {
	o.watcher.Start()
	o.istioMonitor.Start()
	return nil
}

func (o *sslProgram) PostStart(*manager.Manager) error {
	return nil
}

func (o *sslProgram) Stop(*manager.Manager) {
	o.watcher.Stop()
	o.istioMonitor.Stop()
}

func (o *sslProgram) DumpMaps(w io.Writer, mapName string, currentMap *ebpf.Map) {
	switch mapName {
	case sslSockByCtxMap: // maps/ssl_sock_by_ctx (BPF_MAP_TYPE_HASH), key uintptr // C.void *, value C.ssl_sock_t
		io.WriteString(w, "Map: '"+mapName+"', key: 'uintptr // C.void *', value: 'C.ssl_sock_t'\n")
		iter := currentMap.Iterate()
		var key uintptr // C.void *
		var value http.SslSock
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			spew.Fdump(w, key, value)
		}

	case "ssl_read_args": // maps/ssl_read_args (BPF_MAP_TYPE_HASH), key C.__u64, value C.ssl_read_args_t
		io.WriteString(w, "Map: '"+mapName+"', key: 'C.__u64', value: 'C.ssl_read_args_t'\n")
		iter := currentMap.Iterate()
		var key uint64
		var value http.SslReadArgs
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			spew.Fdump(w, key, value)
		}

	case "bio_new_socket_args": // maps/bio_new_socket_args (BPF_MAP_TYPE_HASH), key C.__u64, value C.__u32
		io.WriteString(w, "Map: '"+mapName+"', key: 'C.__u64', value: 'C.__u32'\n")
		iter := currentMap.Iterate()
		var key uint64
		var value uint32
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			spew.Fdump(w, key, value)
		}

	case "fd_by_ssl_bio": // maps/fd_by_ssl_bio (BPF_MAP_TYPE_HASH), key C.__u32, value uintptr // C.void *
		io.WriteString(w, "Map: '"+mapName+"', key: 'C.__u32', value: 'uintptr // C.void *'\n")
		iter := currentMap.Iterate()
		var key uint32
		var value uintptr // C.void *
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			spew.Fdump(w, key, value)
		}

	case "ssl_ctx_by_pid_tgid": // maps/ssl_ctx_by_pid_tgid (BPF_MAP_TYPE_HASH), key C.__u64, value uintptr // C.void *
		io.WriteString(w, "Map: '"+mapName+"', key: 'C.__u64', value: 'uintptr // C.void *'\n")
		iter := currentMap.Iterate()
		var key uint64
		var value uintptr // C.void *
		for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
			spew.Fdump(w, key, value)
		}
	}

}

func (o *sslProgram) GetStats() *protocols.ProtocolStats {
	return nil
}

const (
	// Defined in https://man7.org/linux/man-pages/man5/proc.5.html.
	taskCommLen = 16
)

var (
	taskCommLenBufferPool = sync.Pool{
		New: func() any {
			buf := make([]byte, taskCommLen)
			return &buf
		},
	}
)

func isBuildKit(procRoot string, pid uint32) bool {
	filePath := filepath.Join(procRoot, strconv.Itoa(int(pid)), "comm")

	file, err := os.Open(filePath)
	if err != nil {
		// Waiting a bit, as we might get the event of process creation before the directory was created.
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Millisecond)
			// reading again.
			file, err = os.Open(filePath)
			if err == nil {
				break
			}
		}
	}

	buf := taskCommLenBufferPool.Get().(*[]byte)
	defer taskCommLenBufferPool.Put(buf)
	n, err := file.Read(*buf)
	if err != nil {
		// short living process can hit here, or slow start of another process.
		return false
	}
	return bytes.Equal(bytes.TrimSpace((*buf)[:n]), buildKitProcessName)
}

func addHooks(m *manager.Manager, procRoot string, probes []manager.ProbesSelector) func(utils.FilePath) error {
	return func(fpath utils.FilePath) error {
		if isBuildKit(procRoot, fpath.PID) {
			return fmt.Errorf("process %d is buildkitd, skipping", fpath.PID)
		}

		uid := getUID(fpath.ID)

		elfFile, err := elf.Open(fpath.HostPath)
		if err != nil {
			return err
		}
		defer elfFile.Close()

		symbolsSet := make(common.StringSet)
		symbolsSetBestEffort := make(common.StringSet)
		for _, singleProbe := range probes {
			_, isBestEffort := singleProbe.(*manager.BestEffort)
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				_, symbol, ok := strings.Cut(selector.EBPFFuncName, "__")
				if !ok {
					continue
				}
				if isBestEffort {
					symbolsSetBestEffort[symbol] = struct{}{}
				} else {
					symbolsSet[symbol] = struct{}{}
				}
			}
		}
		symbolMap, err := bininspect.GetAllSymbolsByName(elfFile, symbolsSet)
		if err != nil {
			return err
		}
		/* Best effort to resolve symbols, so we don't care about the error */
		symbolMapBestEffort, _ := bininspect.GetAllSymbolsByName(elfFile, symbolsSetBestEffort)

		for _, singleProbe := range probes {
			_, isBestEffort := singleProbe.(*manager.BestEffort)
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				identifier := manager.ProbeIdentificationPair{
					EBPFFuncName: selector.EBPFFuncName,
					UID:          uid,
				}
				singleProbe.EditProbeIdentificationPair(selector, identifier)
				probe, found := m.GetProbe(identifier)
				if found {
					if !probe.IsRunning() {
						err := probe.Attach()
						if err != nil {
							return err
						}
					}

					continue
				}

				_, symbol, ok := strings.Cut(selector.EBPFFuncName, "__")
				if !ok {
					continue
				}

				sym := symbolMap[symbol]
				if isBestEffort {
					sym, found = symbolMapBestEffort[symbol]
					if !found {
						continue
					}
				}
				manager.SanitizeUprobeAddresses(elfFile, []elf.Symbol{sym})
				offset, err := bininspect.SymbolToOffset(elfFile, sym)
				if err != nil {
					return err
				}

				newProbe := &manager.Probe{
					ProbeIdentificationPair: identifier,
					BinaryPath:              fpath.HostPath,
					UprobeOffset:            uint64(offset),
					HookFuncName:            symbol,
				}
				if err := m.AddHook("", newProbe); err == nil {
					ebpfcheck.AddProgramNameMapping(newProbe.ID(), newProbe.EBPFFuncName, "usm_tls")
				}
			}
			if err := singleProbe.RunValidator(m); err != nil {
				return err
			}
		}

		return nil
	}
}

func removeHooks(m *manager.Manager, probes []manager.ProbesSelector) func(utils.FilePath) error {
	return func(fpath utils.FilePath) error {
		uid := getUID(fpath.ID)
		for _, singleProbe := range probes {
			for _, selector := range singleProbe.GetProbesIdentificationPairList() {
				identifier := manager.ProbeIdentificationPair{
					EBPFFuncName: selector.EBPFFuncName,
					UID:          uid,
				}
				probe, found := m.GetProbe(identifier)
				if !found {
					continue
				}

				program := probe.Program()
				err := m.DetachHook(identifier)
				if err != nil {
					log.Debugf("detach hook %s/%s : %s", selector.EBPFFuncName, uid, err)
				}
				if program != nil {
					program.Close()
				}
			}
		}

		return nil
	}
}

// getUID() return a key of length 5 as the kernel uprobe registration path is limited to a length of 64
// ebpf-manager/utils.go:GenerateEventName() MaxEventNameLen = 64
// MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
//
// Length 5 is arbitrary value as the full string of the eventName format is
//
//	fmt.Sprintf("%s_%.*s_%s_%s", probeType, maxFuncNameLen, functionName, UID, attachPIDstr)
//
// functionName is variable but with a minimum guarantee of 10 chars
func getUID(lib utils.PathIdentifier) string {
	return lib.Key()[:5]
}

// IsBuildModeSupported returns always true, as tls module is supported by all modes.
func (*sslProgram) IsBuildModeSupported(buildmode.Type) bool {
	return true
}
