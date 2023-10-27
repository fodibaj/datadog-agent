// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package flare contains helpers and e2e tests of the flare command
package flare

import (
	_ "embed"
	"strings"
	"testing"
	"time"

	fakeintake "github.com/DataDog/datadog-agent/test/fakeintake/client"
	"github.com/DataDog/datadog-agent/test/fakeintake/client/flare"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client"
	"github.com/DataDog/test-infra-definitions/components/datadog/agentparams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type commandFlareSuite struct {
	e2e.Suite[e2e.FakeIntakeEnv]
}

func TestFlareSuite(t *testing.T) {
	e2e.Run(t, &commandFlareSuite{}, e2e.FakeIntakeStackDef())
}

func requestAgentFlareAndFetchFromFakeIntake(t *testing.T, agent client.Agent, fakeintake *fakeintake.Client, flareArgs ...client.AgentArgsOption) flare.Flare {
	// Wait for the fakeintake to be ready to avoid 503 when sending the flare
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NoError(c, fakeintake.GetServerHealth())
	}, 5*time.Minute, 20*time.Second, "expected fakeintake server to be ready; not ready in 5min")

	_ = agent.Flare(flareArgs...)

	flare, err := fakeintake.GetLatestFlare()
	require.NoError(t, err)

	return flare
}

func (v *commandFlareSuite) TestFlareDefaultFiles() {
	flare := requestAgentFlareAndFetchFromFakeIntake(v.T(), v.Env().Agent, v.Env().Fakeintake.Client, client.WithArgs([]string{"--email", "e2e@test.com", "--send"}))

	assertFilesExist(v.T(), flare, defaultFlareFiles)
	assertFilesExist(v.T(), flare, defaultLogFiles)
	assertFilesExist(v.T(), flare, defaultConfigFiles)
	assertFoldersExist(v.T(), flare, defaultFlareFolders)

	assertFileContains(v.T(), flare, "process_check_output.json", "'process_config.process_collection.enabled' is disabled")
	assertFileNotContains(v.T(), flare, "container_check_output.json", "'process_config.container_collection.enabled' is disabled")
	assertFileNotContains(v.T(), flare, "process_discovery_check_output.json", "'process_config.process_discovery.enabled' is disabled")

	assertLogsFolderOnlyContainsLogFile(v.T(), flare)
	assertEtcFolderOnlyContainsConfigFile(v.T(), flare)
}

//go:embed fixtures/datadog-agent.yaml
var agentConfiguration []byte

//go:embed fixtures/system-probe.yaml
var systemProbeConfiguration []byte

//go:embed fixtures/security-agent.yaml
var securityAgentConfiguration []byte

func (v *commandFlareSuite) TestFlareWithAllConfiguration() {

	var scenarioExpectedFiles = []string{
		"telemetry.log",       // if telemetry.enabled
		"registry.json",       // if Logs Agent is running
		"expvar/system-probe", // if system probe is enabled
	}

	systemProbeDummyFiles := []string{"/tmp/dummy_dir", "/tmp/dummy_system_probe_config_bpf_dir"}
	v.Env().VM.Execute("sudo mkdir -p " + strings.Join(systemProbeDummyFiles, " "))

	confdPath := "/opt/datadog-agent/bin/agent/dist/conf.d/"
	useSudo := true

	withFiles := []agentparams.Option{
		// TODO: use dedicated functions when https://github.com/DataDog/test-infra-definitions/pull/309 is merged
		agentparams.WithSystemProbeConfig(string(systemProbeConfiguration)),
		agentparams.WithSecurityAgentConfig(string(securityAgentConfiguration)),
		agentparams.WithFile(confdPath+"test.yaml", "dummy content", useSudo),
		agentparams.WithFile(confdPath+"test.yml", "dummy content", useSudo),
		agentparams.WithFile(confdPath+"test.yml.test", "dummy content", useSudo),
		agentparams.WithFile("/opt/datadog-agent/checks.d/test.yml", "dummy content", useSudo),
	}

	agentOptions := append(withFiles, agentparams.WithAgentConfig(string(agentConfiguration)))

	v.UpdateEnv(e2e.FakeIntakeStackDef(e2e.WithAgentParams(agentOptions...)))

	flare := requestAgentFlareAndFetchFromFakeIntake(v.T(), v.Env().Agent, v.Env().Fakeintake.Client, client.WithArgs([]string{"--email", "e2e@test.com", "--send"}))

	assertFilesExist(v.T(), flare, scenarioExpectedFiles)
	assertFilesExist(v.T(), flare, allLogFiles)
	// XXX: this test is expected to fail because 'etc/security-agent.yaml' is not found. See #18463
	assertFilesExist(v.T(), flare, allConfigFiles)

	extraCustomConfigFiles := []string{"etc/confd/dist/test.yaml", "etc/confd/dist/test.yml", "etc/confd/dist/test.yml.test", "etc/confd/checksd/test.yml"}
	assertFilesExist(v.T(), flare, extraCustomConfigFiles)

	assertFileNotContains(v.T(), flare, "process_check_output.json", "'process_config.process_collection.enabled' is disabled")
	assertFileContains(v.T(), flare, "container_check_output.json", "'process_config.container_collection.enabled' is disabled")
	assertFileContains(v.T(), flare, "process_discovery_check_output.json", "'process_config.process_discovery.enabled' is disabled")

	filesRegistredInPermissionsLog := append(systemProbeDummyFiles, "/etc/datadog-agent/auth_token")
	assertFileContains(v.T(), flare, "permissions.log", filesRegistredInPermissionsLog...)
}
