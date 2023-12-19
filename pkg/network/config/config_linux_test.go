// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"

	aconfig "github.com/DataDog/datadog-agent/pkg/config"
)

func TestDisableRootNetNamespace(t *testing.T) {
	aconfig.ResetSystemProbeConfig(t)
	t.Setenv("DD_NETWORK_CONFIG_ENABLE_ROOT_NETNS", "false")

	cfg := New()
	require.False(t, cfg.EnableConntrackAllNamespaces)
	require.False(t, cfg.EnableRootNetNs)

	rootNs, err := cfg.GetRootNetNs()
	require.NoError(t, err)
	defer rootNs.Close()
	require.False(t, netns.None().Equal(rootNs))

	ns, err := netns.GetFromPid(os.Getpid())
	require.NoError(t, err)
	defer ns.Close()
	require.True(t, ns.Equal(rootNs))
}

func newSystemProbeConfig(t *testing.T) {
	originalConfig := aconfig.SystemProbe
	t.Cleanup(func() {
		aconfig.SystemProbe = originalConfig
	})
	aconfig.SystemProbe = aconfig.NewConfig("system-probe", "DD", strings.NewReplacer(".", "_"))
	aconfig.InitSystemProbeConfig(aconfig.SystemProbe)
}
