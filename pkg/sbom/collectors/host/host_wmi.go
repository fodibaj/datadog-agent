// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !trivy && windows

package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"

	cyclonedxgo "github.com/CycloneDX/cyclonedx-go"
	"github.com/yusufpapurcu/wmi"
)

// Win32QuickFixEngineering WMI class represents a small system-wide update, commonly referred to as a quick-fix engineering
type Win32QuickFixEngineering struct {
	Name        string
	Status      string
	HotFixID    string
	Description string
}

// Report describes a SBOM report along with its marshaler
type Report struct {
	KBS  []Win32QuickFixEngineering
	hash []byte
}

// ToCycloneDX returns the report as a CycloneDX SBOM
func (r *Report) ToCycloneDX() (*cyclonedxgo.BOM, error) {
	hash := sha256.New()

	var components []cyclonedxgo.Component

	winVer, err := winutil.GetWindowsBuildString()
	if err != nil {
		return nil, err
	}

	components = append(components, cyclonedxgo.Component{
		Type:    cyclonedxgo.ComponentTypeOS,
		Name:    "Windows",
		Version: winVer,
	})

	for _, kb := range r.KBS {
		components = append(components, cyclonedxgo.Component{
			Name: kb.HotFixID,
			Type: cyclonedxgo.ComponentTypeFile,
		})
		hash.Write([]byte(kb.HotFixID))
	}

	r.hash = hash.Sum(nil)

	return &cyclonedxgo.BOM{
		Components: &components,
	}, nil
}

// ID returns the report identifier
func (r *Report) ID() string {
	return hex.EncodeToString(r.hash)
}

// Collector defines a host collector
type Collector struct {
}

// CleanCache cleans the cache
func (c *Collector) CleanCache() error {
	return nil
}

// Init initialize the host collector
func (c *Collector) Init(_ config.Config) error {
	return nil
}

// Scan performs a scan
func (c *Collector) Scan(_ context.Context, request sbom.ScanRequest, _ sbom.ScanOptions) sbom.ScanResult {
	hostScanRequest, ok := request.(*ScanRequest)
	if !ok {
		return sbom.ScanResult{Error: fmt.Errorf("invalid request type '%s' for collector '%s'", reflect.TypeOf(request), collectorName)}
	}
	log.Infof("host scan request [%v]", hostScanRequest.ID())

	var report Report
	q := wmi.CreateQuery(&report.KBS, "")
	err := wmi.Query(q, &report.KBS)
	if err != nil {
		return sbom.ScanResult{
			Error: err,
		}
	}

	return sbom.ScanResult{
		Error:  err,
		Report: &report,
	}
}
