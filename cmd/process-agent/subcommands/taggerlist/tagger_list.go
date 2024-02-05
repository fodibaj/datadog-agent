// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//nolint:revive // TODO(PROC) Fix revive linter
package app

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/cmd/process-agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	tagger_api "github.com/DataDog/datadog-agent/comp/core/tagger/api"
	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

const taggerListURLTpl = "http://%s/agent/tagger-list"

// Commands returns a slice of subcommands for the `tagger-list` command in the Process Agent
func Commands(globalParams *command.GlobalParams) []*cobra.Command {
	taggerCmd := &cobra.Command{
		Use:   "tagger-list",
		Short: "Print the tagger content of a running agent",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(taggerList,
				fx.Supply(command.GetCoreBundleParamsForOneShot(globalParams)),

				core.Bundle(),
			)
		},
		SilenceUsage: true,
	}

	return []*cobra.Command{taggerCmd}
}

type dependencies struct {
	fx.In

	Config config.Component
	Log    log.Component
}

func taggerList(deps dependencies) error {
	deps.Log.Info("Got a request for the tagger-list. Calling tagger.")

	taggerURL, err := getTaggerURL()
	if err != nil {
		return err
	}

	return tagger_api.GetTaggerList(color.Output, taggerURL)
}

func getTaggerURL() (string, error) {
	addressPort, err := ddconfig.GetProcessAPIAddressPort()
	if err != nil {
		return "", fmt.Errorf("config error: %s", err.Error())
	}
	return fmt.Sprintf(taggerListURLTpl, addressPort), nil
}
