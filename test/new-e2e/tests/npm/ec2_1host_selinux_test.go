// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package npm

import (
	"testing"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	awshost "github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/host"

	compos "github.com/DataDog/test-infra-definitions/components/os"
	"github.com/DataDog/test-infra-definitions/scenarios/aws/ec2"
)

type ec2VMSELinuxSuite struct {
	e2e.BaseSuite[hostHttpbinEnv]
}

// TestEC2VMSuite will validate running the agent on a single EC2 VM
func TestEC2VMSELinuxSuite(t *testing.T) {
	s := &ec2VMSELinuxSuite{}

	e2eParams := []e2e.SuiteOption{e2e.WithProvisioner(
		e2e.NewTypedPulumiProvisioner("hostHttpbin", hostDockerHttpbinEnvProvisioner(awshost.WithEC2InstanceOptions(ec2.WithAMI("ami-0339ee0a14a92573d", compos.AmazonLinux2, compos.ARM64Arch), ec2.WithInstanceType("c6g.medium"))), nil)),
	}

	// Source of our kitchen CI images test/kitchen/platforms.json
	// Other VM image can be used, our kitchen CI images test/kitchen/platforms.json
	// ec2params.WithImageName("ami-a4dc46db", os.AMD64Arch, ec2os.AmazonLinuxOS) // ubuntu-16-04-4.4
	e2e.Run(t, s, e2eParams...)
}

// BeforeTest will be called before each test
func (v *ec2VMSELinuxSuite) BeforeTest(suiteName, testName string) {
	v.BaseSuite.BeforeTest(suiteName, testName)
	v.beforeTest(suiteName, testName)
}

func (v *ec2VMSELinuxSuite) beforeTest(_, _ string) {
	// default is to reset the current state of the fakeintake aggregators
	if !v.BaseSuite.IsDevMode() {
		v.Env().FakeIntake.Client().FlushServerAndResetAggregators()
	}
}

func (v *ec2VMSELinuxSuite) SetupSuite() {
	v.BaseSuite.SetupSuite()

	v.Env().RemoteHost.MustExecute("sudo yum install -y bind-utils httpd-tools")
	v.Env().RemoteHost.MustExecute("sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo")
	v.Env().RemoteHost.MustExecute("sudo yum install -y docker-ce docker-ce-cli")
	v.Env().RemoteHost.MustExecute("sudo systemctl start docker")
	v.Env().RemoteHost.MustExecute("sudo usermod -a -G docker $(whoami)")
	v.Env().RemoteHost.ReconnectSSH()

	// prefetch docker image locally
	v.Env().RemoteHost.MustExecute("docker run curlimages/curl --version")
	v.Env().RemoteHost.MustExecute("docker run devth/alpine-bench -V")
	v.Env().RemoteHost.MustExecute("docker run makocchi/alpine-dig dig")
}

// TestFakeIntakeNPM Validate the agent can communicate with the (fake) backend and send connections every 30 seconds
// 2 tests generate the request on the host and on docker
//   - looking for 1 host to send CollectorConnections payload to the fakeintake
//   - looking for 3 payloads and check if the last 2 have a span of 30s +/- 500ms
func (v *ec2VMSELinuxSuite) TestFakeIntakeNPM() {
	vt := v.T()
	testURL := "http://" + v.Env().HTTPBinHost.Address + "/"
	vt.Run("host_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate a connection
		v.Env().RemoteHost.MustExecute("curl " + testURL)

		test1HostFakeIntakeNPM(&v.BaseSuite, v.Env().FakeIntake)
	})
	vt.Run("docker_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate a connection
		v.Env().RemoteHost.MustExecute("docker run curlimages/curl curl " + testURL)

		test1HostFakeIntakeNPM(&v.BaseSuite, v.Env().FakeIntake)
	})
}

// TestFakeIntakeNPM_600cnx_bucket Validate the agent can communicate with the (fake) backend and send connections
// every 30 seconds with a maximum of 600 connections per payloads, if more another payload will follow.
//   - looking for 1 host to send CollectorConnections payload to the fakeintake
//   - looking for n payloads and check if the last 2 have a maximum span of 100ms
func (v *ec2VMSELinuxSuite) TestFakeIntakeNPM_600cnx_bucket() {
	vt := v.T()
	testURL := "http://" + v.Env().HTTPBinHost.Address + "/"
	vt.Run("host_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate connections
		v.Env().RemoteHost.MustExecute("ab -n 600 -c 600 " + testURL)

		test1HostFakeIntakeNPM600cnxBucket(&v.BaseSuite, v.Env().FakeIntake)
	})
	vt.Run("docker_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate connections
		v.Env().RemoteHost.MustExecute("docker run devth/alpine-bench -n 600 -c 600 " + testURL)

		test1HostFakeIntakeNPM600cnxBucket(&v.BaseSuite, v.Env().FakeIntake)
	})
}

// TestFakeIntakeNPM_TCP_UDP_DNS validate we received tcp, udp, and DNS connections
// with some basic checks, like IPs/Ports present, DNS query has been captured, ...
func (v *ec2VMSELinuxSuite) TestFakeIntakeNPM_TCP_UDP_DNS() {
	vt := v.T()
	testURL := "http://" + v.Env().HTTPBinHost.Address + "/"
	vt.Run("host_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate connections
		v.Env().RemoteHost.MustExecute("curl " + testURL)
		v.Env().RemoteHost.MustExecute("dig @8.8.8.8 www.google.ch")

		test1HostFakeIntakeNPMTCPUDPDNS(&v.BaseSuite, v.Env().FakeIntake)
	})
	vt.Run("docker_requests", func(t *testing.T) {
		v.BaseSuite.SetT(t)
		v.beforeTest("TestEC2VMSELinuxSuite", t.Name()) // workaround as suite doesn't call BeforeTest before each sub tests

		// generate connections
		v.Env().RemoteHost.MustExecute("docker run curlimages/curl curl " + testURL)
		v.Env().RemoteHost.MustExecute("docker run makocchi/alpine-dig dig @8.8.8.8 www.google.ch")

		test1HostFakeIntakeNPMTCPUDPDNS(&v.BaseSuite, v.Env().FakeIntake)
	})
}
