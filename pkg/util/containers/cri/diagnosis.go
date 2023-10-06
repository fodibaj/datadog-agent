// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build cri

package cri

import (
	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"
)

func init() {
	diagnosis.RegisterMetadataAvail("CRI availability", diagnose)
}

// diagnose the CRI socket connectivity
func diagnose() error {
	_, err := GetUtil()
	return err
}
