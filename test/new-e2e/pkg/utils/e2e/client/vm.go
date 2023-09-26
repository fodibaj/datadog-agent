// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package client contains clients used to communicate with the remote service
package client

import (
	"os"
	"testing"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/runner"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/runner/parameters"
	commonos "github.com/DataDog/test-infra-definitions/components/os"
	commonvm "github.com/DataDog/test-infra-definitions/components/vm"
)

var _ clientService[commonvm.ClientData] = (*VM)(nil)

// VM is a client VM that is connected to a VM defined in test-infra-definition.
type VM struct {
	*UpResultDeserializer[commonvm.ClientData]
	*vmClient
	OS commonos.OS
}

// NewVM creates a new instance of VM
func NewVM(infraVM commonvm.VM) *VM {
	vm := &VM{}
	vm.OS = infraVM.GetOS()
	vm.UpResultDeserializer = NewUpResultDeserializer[commonvm.ClientData](infraVM, vm)
	return vm
}

//lint:ignore U1000 Ignore unused function as this function is call using reflection
func (vm *VM) initService(t *testing.T, data *commonvm.ClientData) error {
	var err error
	var privateSSHKey []byte

	privateKeyPath, err := runner.GetProfile().ParamStore().GetWithDefault(parameters.PrivateKeyPath, "")
	if err != nil {
		return err
	}

	if privateKeyPath != "" {
		privateSSHKey, err = os.ReadFile(privateKeyPath)
		if err != nil {
			return err
		}
	}

	vm.vmClient, err = newVMClient(t, privateSSHKey, &data.Connection)
	return err
}
