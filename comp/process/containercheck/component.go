// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package containercheck implements a component to handle Container data collection in the Process Agent.
package containercheck

import (
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/process/types"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// team: processes

// Component exported type should have comment or be unexported
type Component interface {
	types.CheckComponent
}

// Module defines the fx options for this component.
var Module = fxutil.Component(
	fx.Provide(newCheck),
)

// MockModule exported var should have comment or be unexported
var MockModule = fxutil.Component(
	fx.Provide(newMock),
)
