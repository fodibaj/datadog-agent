// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package usm

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/cihub/seelog"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/atomic"

	manager "github.com/DataDog/ebpf-manager"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/ebpf/probe/ebpfcheck"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/ebpf/probes"
	filterpkg "github.com/DataDog/datadog-agent/pkg/network/filter"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http2"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/kafka"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	errtelemetry "github.com/DataDog/datadog-agent/pkg/network/telemetry"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type monitorState = string

const (
	Disabled          monitorState = "Disabled"
	Running           monitorState = "Running"
	NotRunning        monitorState = "Not Running"
	monitorModuleName              = "http2_monitor__ebpf"
)

var (
	state        = Disabled
	startupError error

	// knownProtocols holds all known protocols supported by USM to initialize.
	knownProtocols = []*protocols.ProtocolSpec{
		http.Spec,
		http2.Spec,
		kafka.Spec,
		javaTLSSpec,
		// opensslSpec is unique, as we're modifying its factory during runtime to allow getting more parameters in the
		// factory.
		opensslSpec,
	}
)

var MonitorTelemetry = struct {
	EndOfStreamEOS           *prometheus.Desc
	EndOfStreamRST           *prometheus.Desc
	StrLenGraterThenFrameLoc *prometheus.Desc
	StrLenTooBigMid          *prometheus.Desc
	StrLenTooBigLarge        *prometheus.Desc
	RequestSeen              *prometheus.Desc
	ResponseSeen             *prometheus.Desc
	FrameRemainder           *prometheus.Desc
	MaxFramesInPacket        *prometheus.Desc

	LastEndOfStreamEOS           *atomic.Int64
	LastEndOfStreamRST           *atomic.Int64
	LastStrLenGraterThenFrameLoc *atomic.Int64
	LastStrLenTooBigMid          *atomic.Int64
	LastStrLenTooBigLarge        *atomic.Int64
	LastRequestSeen              *atomic.Int64
	LastResponseSeen             *atomic.Int64
	LastFrameRemainder           *atomic.Int64
	LastMaxFramesInPacket        *atomic.Int64
}{
	prometheus.NewDesc(monitorModuleName+"__end_of_stream_eos", "Counter measuring the number of times we seem EOS flag", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__end_of_stream_rst", "Counter measuring the number of times we seem EOS due to RST", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__str_len_greater_then_frame_loc", "Counter measuring the number of times we reached the max size of frame due to path size to big", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__str_len_too_big_mid", "Counter measuring the number of times we reached the max size of string that is bigger the 160", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__str_len_too_big_large", "Counter measuring the number of times we reached the max size of string that is bigger the 180", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__request_seen", "Counter measuring the number of times seem request", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__response_seen", "Counter measuring the number of times seem response", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__frame_remainder", "Counter measuring the number of times we seen from had remainder response", nil, nil),
	prometheus.NewDesc(monitorModuleName+"__max_frames_in_packet", "Counter measuring the number of times we passed the max amount we can process in a packet", nil, nil),

	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
	atomic.NewInt64(0),
}

var errNoProtocols = errors.New("no protocol monitors were initialised")

// Monitor is responsible for:
// * Creating a raw socket and attaching an eBPF filter to it;
// * Consuming HTTP transaction "events" that are sent from Kernel space;
// * Aggregating and emitting metrics based on the received HTTP transactions;
type Monitor struct {
	cfg *config.Config

	enabledProtocols []protocols.Protocol

	ebpfProgram *ebpfProgram

	processMonitor *monitor.ProcessMonitor

	// termination
	closeFilterFn func()

	lastUpdateTime *atomic.Int64
}

// NewMonitor returns a new Monitor instance
func NewMonitor(c *config.Config, connectionProtocolMap, sockFD *ebpf.Map, bpfTelemetry *errtelemetry.EBPFTelemetry) (m *Monitor, err error) {
	defer func() {
		// capture error and wrap it
		if err != nil {
			state = NotRunning
			err = fmt.Errorf("could not initialize USM: %w", err)
			startupError = err
		}
	}()

	mgr, err := newEBPFProgram(c, sockFD, connectionProtocolMap, bpfTelemetry)
	if err != nil {
		return nil, fmt.Errorf("error setting up ebpf program: %w", err)
	}

	opensslSpec.Factory = newSSLProgramProtocolFactory(mgr.Manager.Manager, sockFD, bpfTelemetry)

	enabledProtocols, disabledProtocols, err := initProtocols(c, mgr)
	if err != nil {
		return nil, err
	}
	if len(enabledProtocols) == 0 {
		state = Disabled
		log.Debug("not enabling USM as no protocols monitoring were enabled.")
		return nil, nil
	}

	mgr.enabledProtocols = enabledProtocols
	mgr.disabledProtocols = disabledProtocols

	if err := mgr.Init(); err != nil {
		return nil, fmt.Errorf("error initializing ebpf program: %w", err)
	}

	filter, _ := mgr.GetProbe(manager.ProbeIdentificationPair{EBPFFuncName: protocolDispatcherSocketFilterFunction, UID: probeUID})
	if filter == nil {
		return nil, fmt.Errorf("error retrieving socket filter")
	}
	ebpfcheck.AddNameMappings(mgr.Manager.Manager, "usm_monitor")

	closeFilterFn, err := filterpkg.HeadlessSocketFilter(c, filter)
	if err != nil {
		return nil, fmt.Errorf("error enabling traffic inspection: %s", err)
	}

	processMonitor := monitor.GetProcessMonitor()

	state = Running

	usmMonitor := &Monitor{
		cfg:              c,
		enabledProtocols: enabledProtocols,
		ebpfProgram:      mgr,
		closeFilterFn:    closeFilterFn,
		processMonitor:   processMonitor,
	}

	usmMonitor.lastUpdateTime = atomic.NewInt64(time.Now().Unix())

	return usmMonitor, nil
}

// Start USM monitor.
func (m *Monitor) Start() error {
	if m == nil {
		return nil
	}

	var err error

	defer func() {
		if err != nil {
			if errors.Is(err, syscall.ENOMEM) {
				err = fmt.Errorf("could not enable usm monitoring: not enough memory to attach http ebpf socket filter. please consider raising the limit via sysctl -w net.core.optmem_max=<LIMIT>")
			} else {
				err = fmt.Errorf("could not enable USM: %s", err)
			}

			m.Stop()

			startupError = err
		}
	}()

	// Deleting from an array while iterating it is not a simple task. Instead, every successfully enabled protocol,
	// we'll keep it in a temporary copy, and in case of a mismatch (a.k.a., we have a failed protocols) between
	// enabledProtocolsTmp to m.enabledProtocols, we'll use the enabledProtocolsTmp.
	enabledProtocolsTmp := m.enabledProtocols[:0]
	for _, protocol := range m.enabledProtocols {
		startErr := protocol.PreStart(m.ebpfProgram.Manager.Manager)
		if startErr != nil {
			log.Errorf("could not complete pre-start phase of %s monitoring: %s", protocol.Name(), startErr)
			continue
		}
		enabledProtocolsTmp = append(enabledProtocolsTmp, protocol)
	}
	m.enabledProtocols = enabledProtocolsTmp

	// No protocols could be enabled, abort.
	if len(m.enabledProtocols) == 0 {
		return errNoProtocols
	}

	err = m.ebpfProgram.Start()
	if err != nil {
		return err
	}

	enabledProtocolsTmp = m.enabledProtocols[:0]
	for _, protocol := range m.enabledProtocols {
		startErr := protocol.PostStart(m.ebpfProgram.Manager.Manager)
		if startErr != nil {
			// Cleanup the protocol. Note that at this point we can't unload the
			// ebpf programs of a specific protocol without shutting down the
			// entire manager.
			protocol.Stop(m.ebpfProgram.Manager.Manager)

			// Log and reset the error value
			log.Errorf("could not complete post-start phase of %s monitoring: %s", protocol.Name(), startErr)
			continue
		}
		enabledProtocolsTmp = append(enabledProtocolsTmp, protocol)
	}
	m.enabledProtocols = enabledProtocolsTmp

	// We check again if there are protocols that could be enabled, and abort if
	// it is not the case.
	if len(m.enabledProtocols) == 0 {
		err = m.ebpfProgram.Close()
		if err != nil {
			log.Errorf("error during USM shutdown: %s", err)
		}

		return errNoProtocols
	}

	// Need to explicitly save the error in `err` so the defer function could save the startup error.
	if m.cfg.EnableNativeTLSMonitoring || m.cfg.EnableGoTLSSupport || m.cfg.EnableJavaTLSSupport || m.cfg.EnableIstioMonitoring {
		err = m.processMonitor.Initialize()
	}

	for _, protocolName := range m.enabledProtocols {
		log.Infof("enabled USM protocol: %s", protocolName.Name())
	}

	return err
}

func (m *Monitor) GetUSMStats() map[string]interface{} {
	response := map[string]interface{}{
		"state": state,
	}

	if startupError != nil {
		response["error"] = startupError.Error()
	}

	if m != nil {
		response["last_check"] = m.lastUpdateTime
	}
	return response
}

func (m *Monitor) GetProtocolStats() map[protocols.ProtocolType]interface{} {
	if m == nil {
		return nil
	}

	defer func() {
		// Update update time
		now := time.Now().Unix()
		m.lastUpdateTime.Swap(now)
		telemetry.ReportPrometheus()
	}()

	ret := make(map[protocols.ProtocolType]interface{})

	for _, protocol := range m.enabledProtocols {
		ps := protocol.GetStats()
		if ps != nil {
			ret[ps.Type] = ps.Stats
		}
	}

	return ret
}

// Stop HTTP monitoring
func (m *Monitor) Stop() {
	if m == nil {
		return
	}

	m.processMonitor.Stop()

	ebpfcheck.RemoveNameMappings(m.ebpfProgram.Manager.Manager)
	for _, protocol := range m.enabledProtocols {
		protocol.Stop(m.ebpfProgram.Manager.Manager)
	}

	m.ebpfProgram.Close()
	m.closeFilterFn()
}

// DumpMaps dumps the maps associated with the monitor
func (m *Monitor) DumpMaps(maps ...string) (string, error) {
	return m.ebpfProgram.DumpMaps(maps...)
}

func (m *Monitor) getHTTP2EBPFTelemetry() *netebpf.HTTP2Telemetry {
	var zero uint64
	mp, _, err := m.ebpfProgram.Manager.Manager.GetMap(probes.HTTP2TelemetryMap)
	if err != nil {
		log.Warnf("error retrieving http2 telemetry map: %s", err)
		return nil
	}

	http2Telemetry := &netebpf.HTTP2Telemetry{}
	if err := mp.Lookup(unsafe.Pointer(&zero), unsafe.Pointer(http2Telemetry)); err != nil {
		// This can happen if we haven't initialized the telemetry object yet
		// so let's just use a trace log
		if log.ShouldLog(seelog.TraceLvl) {
			log.Tracef("error retrieving the http2 telemetry struct: %s", err)
		}
		return nil
	}
	return http2Telemetry
}

// Describe returns all descriptions of the collector
func (m *Monitor) Describe(ch chan<- *prometheus.Desc) {
	ch <- MonitorTelemetry.EndOfStreamEOS
	ch <- MonitorTelemetry.EndOfStreamRST
	ch <- MonitorTelemetry.StrLenGraterThenFrameLoc
	ch <- MonitorTelemetry.StrLenTooBigMid
	ch <- MonitorTelemetry.StrLenTooBigLarge
	ch <- MonitorTelemetry.RequestSeen
	ch <- MonitorTelemetry.ResponseSeen
	ch <- MonitorTelemetry.FrameRemainder
	ch <- MonitorTelemetry.MaxFramesInPacket

}

// Collect returns the current state of all metrics of the collector
func (m *Monitor) Collect(ch chan<- prometheus.Metric) {
	http2EbpfTelemetry := m.getHTTP2EBPFTelemetry()
	if http2EbpfTelemetry == nil {
		return
	}

	delta := int64(http2EbpfTelemetry.End_of_stream_eos) - MonitorTelemetry.LastEndOfStreamEOS.Load()
	MonitorTelemetry.LastEndOfStreamEOS.Store(int64(http2EbpfTelemetry.End_of_stream_eos))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.EndOfStreamEOS, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.End_of_stream_rst) - MonitorTelemetry.LastEndOfStreamRST.Load()
	MonitorTelemetry.LastEndOfStreamRST.Store(int64(http2EbpfTelemetry.End_of_stream_rst))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.EndOfStreamRST, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Str_len_greater_then_frame_loc) - MonitorTelemetry.LastStrLenGraterThenFrameLoc.Load()
	MonitorTelemetry.LastStrLenGraterThenFrameLoc.Store(int64(http2EbpfTelemetry.Str_len_greater_then_frame_loc))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.StrLenGraterThenFrameLoc, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Str_len_too_big_mid) - MonitorTelemetry.LastStrLenTooBigMid.Load()
	MonitorTelemetry.LastStrLenTooBigMid.Store(int64(http2EbpfTelemetry.Str_len_too_big_mid))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.StrLenTooBigMid, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Str_len_too_big_large) - MonitorTelemetry.LastStrLenTooBigLarge.Load()
	MonitorTelemetry.LastStrLenTooBigLarge.Store(int64(http2EbpfTelemetry.Str_len_too_big_large))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.StrLenTooBigLarge, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Request_seen) - MonitorTelemetry.LastRequestSeen.Load()
	MonitorTelemetry.LastRequestSeen.Store(int64(http2EbpfTelemetry.Request_seen))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.RequestSeen, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Response_seen) - MonitorTelemetry.LastResponseSeen.Load()
	MonitorTelemetry.LastResponseSeen.Store(int64(http2EbpfTelemetry.Response_seen))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.ResponseSeen, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Frame_remainder) - MonitorTelemetry.LastFrameRemainder.Load()
	MonitorTelemetry.LastFrameRemainder.Store(int64(http2EbpfTelemetry.Frame_remainder))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.FrameRemainder, prometheus.CounterValue, float64(delta))

	delta = int64(http2EbpfTelemetry.Max_frames_in_packet) - MonitorTelemetry.LastMaxFramesInPacket.Load()
	MonitorTelemetry.LastMaxFramesInPacket.Store(int64(http2EbpfTelemetry.Max_frames_in_packet))
	ch <- prometheus.MustNewConstMetric(MonitorTelemetry.MaxFramesInPacket, prometheus.CounterValue, float64(delta))
}

// initProtocols takes the network configuration `c` and uses it to initialise
// the enabled protocols' monitoring, and configures the ebpf-manager `mgr`
// accordingly.
//
// For each enabled protocols, a protocol-specific instance of the Protocol
// interface is initialised, and the required maps and tail calls routers are setup
// in the manager.
//
// If a protocol is not enabled, its tail calls are instead added to the list of
// excluded functions for them to be patched out by ebpf-manager on startup.
//
// It returns:
// - a slice containing instances of the Protocol interface for each enabled protocol support
// - a slice containing pointers to the protocol specs of disabled protocols.
// - an error value, which is non-nil if an error occurred while initialising a protocol
func initProtocols(c *config.Config, mgr *ebpfProgram) ([]protocols.Protocol, []*protocols.ProtocolSpec, error) {
	enabledProtocols := make([]protocols.Protocol, 0)
	disabledProtocols := make([]*protocols.ProtocolSpec, 0)

	for _, spec := range knownProtocols {
		protocol, err := spec.Factory(c)
		if err != nil {
			return nil, nil, &errNotSupported{err}
		}

		if protocol != nil {
			// Configure the manager
			mgr.Maps = append(mgr.Maps, spec.Maps...)
			mgr.Probes = append(mgr.Probes, spec.Probes...)
			mgr.tailCallRouter = append(mgr.tailCallRouter, spec.TailCalls...)

			enabledProtocols = append(enabledProtocols, protocol)

			log.Infof("%v monitoring enabled", protocol.Name())
		} else {
			disabledProtocols = append(disabledProtocols, spec)
		}
	}

	return enabledProtocols, disabledProtocols, nil
}
