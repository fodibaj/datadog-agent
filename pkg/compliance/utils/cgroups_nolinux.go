// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux

package utils

// ContainerID wraps a string representing a container identifier.
type ContainerID string

// GetProcessContainerID returns the container ID associated with the given
// process ID. Returns an empty string if no container found.
func GetProcessContainerID(pid int32) (ContainerID, bool) { //nolint:revive // TODO fix revive unused-parameter
	return "", false
}

// GetProcessRootPath returns the process root path of the given PID.
func GetProcessRootPath(pid int32) (string, bool) { //nolint:revive // TODO fix revive unused-parameter
	return "", false
}
