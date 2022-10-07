// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows
// +build windows

package system

import "errors"

func GetSelfSmapStats(procPath string) (*SelfProcSmaps, error) {
	// TODO, no windows support yet
	return nil, errors.New("Not supported yet")
}
