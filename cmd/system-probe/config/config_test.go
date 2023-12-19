// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux || windows

package config

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/config"
)

func newConfig(t *testing.T) {
	originalConfig := config.SystemProbe
	t.Cleanup(func() {
		config.SystemProbe = originalConfig
	})
	config.SystemProbe = config.NewConfig("system-probe", "DD", strings.NewReplacer(".", "_"))
	config.InitSystemProbeConfig(config.SystemProbe)
}

func TestEventMonitor(t *testing.T) {
	newConfig(t)

	for i, tc := range []struct {
		//nolint:revive // TODO(EBPF) Fix revive linter
		cws, fim, process_events, network_events bool
		enabled                                  bool
	}{
		{cws: false, fim: false, process_events: false, network_events: false, enabled: false},
		{cws: false, fim: false, process_events: true, network_events: false, enabled: true},
		{cws: false, fim: true, process_events: false, network_events: false, enabled: true},
		{cws: false, fim: true, process_events: true, network_events: false, enabled: true},
		{cws: true, fim: false, process_events: false, network_events: false, enabled: true},
		{cws: true, fim: false, process_events: true, network_events: false, enabled: true},
		{cws: true, fim: true, process_events: false, network_events: false, enabled: true},
		{cws: true, fim: true, process_events: true, network_events: false, enabled: true},
		{cws: false, fim: false, process_events: false, network_events: true, enabled: true},
		{cws: false, fim: false, process_events: true, network_events: true, enabled: true},
		{cws: false, fim: true, process_events: false, network_events: true, enabled: true},
		{cws: false, fim: true, process_events: true, network_events: true, enabled: true},
		{cws: true, fim: false, process_events: false, network_events: true, enabled: true},
		{cws: true, fim: false, process_events: true, network_events: true, enabled: true},
		{cws: true, fim: true, process_events: false, network_events: true, enabled: true},
		{cws: true, fim: true, process_events: true, network_events: true, enabled: true},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Logf("%+v\n", tc)
			t.Setenv("DD_RUNTIME_SECURITY_CONFIG_ENABLED", strconv.FormatBool(tc.cws))
			t.Setenv("DD_RUNTIME_SECURITY_CONFIG_FIM_ENABLED", strconv.FormatBool(tc.fim))
			t.Setenv("DD_SYSTEM_PROBE_EVENT_MONITORING_PROCESS_ENABLED", strconv.FormatBool(tc.process_events))
			t.Setenv("DD_SYSTEM_PROBE_EVENT_MONITORING_NETWORK_PROCESS_ENABLED", strconv.FormatBool(tc.network_events))
			t.Setenv("DD_SYSTEM_PROBE_NETWORK_ENABLED", strconv.FormatBool(tc.network_events))

			cfg, err := New("/doesnotexist")
			t.Logf("%+v\n", cfg)
			require.NoError(t, err)
			assert.Equal(t, tc.enabled, cfg.ModuleIsEnabled(EventMonitorModule))
		})
	}
}

func TestEventStreamEnabledForSupportedKernelsWindows(t *testing.T) {
	t.Run("does nothing for windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("This is only for windows")
		}
		aconfig.ResetSystemProbeConfig(t)
		t.Setenv("DD_SYSTEM_PROBE_EVENT_MONITORING_NETWORK_PROCESS_ENABLED", strconv.FormatBool(true))

		cfg := aconfig.SystemProbe
		sysconfig.Adjust(cfg)

		require.False(t, cfg.GetBool("event_monitoring_config.network_process.enabled"))
	})
}
