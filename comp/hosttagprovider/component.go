// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package hosttagprovider ... /* TODO: detailed doc comment for the component */
package hosttagprovider

// team: /* TODO: add team name */

// Component is the component type.
type Component interface {
	HostTags() []string
}
