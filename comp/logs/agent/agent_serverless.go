// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build serverless

package agent

import (
	"context"

	logComponent "github.com/DataDog/datadog-agent/comp/core/log"
	"github.com/DataDog/datadog-agent/comp/logs/agent/config"
	pkgConfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/auditor"
	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/launchers"
	"github.com/DataDog/datadog-agent/pkg/logs/launchers/channel"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/tailers"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"go.uber.org/atomic"
)

// A compat version of the component for the serverless agent exposing the Start and Stop methods
type ServerlessLogsAgent interface {
	Component
	Start() error
	Stop()

	// Flush flushes synchronously the pipelines managed by the Logs Agent.
	Flush(ctx context.Context)
}

func NewServerlessLogsAgent() ServerlessLogsAgent {
	logsAgent := &agent{log: logComponent.NewTemporaryLoggerWithoutInit(), config: pkgConfig.Datadog, started: atomic.NewBool(false)}
	return logsAgent
}

func (a *agent) Start() error {
	return a.start(context.TODO())
}

func (a *agent) Stop() {
	a.stop(context.TODO())
}

// Note: Building the logs-agent for serverless separately removes the
// dependency on autodiscovery, file launchers, and some schedulers
// thereby decreasing the binary size.

// NewAgent returns a Logs Agent instance to run in a serverless environment.
// The Serverless Logs Agent has only one input being the channel to receive the logs to process.
// It is using a NullAuditor because we've nothing to do after having sent the logs to the intake.
func (a *agent) NewAgentState(
	sources *sources.LogSources,
	services *service.Services,
	tracker *tailers.TailerTracker,
	processingRules []*config.ProcessingRule,
	endpoints *config.Endpoints,
) *logsAgentState {
	health := health.RegisterLiveness("logs-agent")

	diagnosticMessageReceiver := diagnostic.NewBufferedMessageReceiver(nil)

	// setup the a null auditor, not tracking data in any registry
	auditor := auditor.NewNullAuditor()
	destinationsCtx := client.NewDestinationsContext()

	// setup the pipeline provider that provides pairs of processor and sender
	pipelineProvider := pipeline.NewServerlessProvider(config.NumberOfPipelines, auditor, processingRules, endpoints, destinationsCtx)

	// setup the sole launcher for this agent
	lnchrs := launchers.NewLaunchers(sources, pipelineProvider, auditor, tracker)
	lnchrs.AddLauncher(channel.NewLauncher())

	return &logsAgentState{
		sources:                   sources,
		services:                  services,
		schedulers:                schedulers.NewSchedulers(sources, services),
		auditor:                   auditor,
		destinationsCtx:           destinationsCtx,
		pipelineProvider:          pipelineProvider,
		launchers:                 lnchrs,
		health:                    health,
		diagnosticMessageReceiver: diagnosticMessageReceiver,
	}
}

// buildEndpoints builds endpoints for the logs agent
func buildEndpoints(coreConfig pkgConfig.ConfigReader) (*config.Endpoints, error) {
	return config.BuildServerlessEndpoints(coreConfig, intakeTrackType, config.DefaultIntakeProtocol)
}

// Flush flushes synchronously the running instance of the Logs Agent.
// Use a WithTimeout context in order to have a flush that can be cancelled.
func (a *agent) Flush(ctx context.Context) {
	if !a.IsRunning() {
		a.log.Info("Can't flush the logs agent because it is not running")
		return
	}

	a.log.Info("Triggering a flush in the logs-agent")
	a.state.pipelineProvider.Flush(ctx)
	a.log.Debug("Flush in the logs-agent done.")
}
