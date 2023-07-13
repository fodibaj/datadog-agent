// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2018-present Datadog, Inc.
//go:build windows

package winutil

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// GetCurrentUserSid returns the windows SID for the current user or an error.
// The *SID returned does not need to be freed by the caller.
func GetCurrentUserSid() (*windows.SID, error) {
	log.Infof("Getting sidstring from user")
	tok, e := syscall.OpenCurrentProcessToken()
	if e != nil {
		log.Warnf("Couldn't get process token %v", e)
		return nil, e
	}
	defer tok.Close()

	user, e := tok.GetTokenUser()
	if e != nil {
		log.Warnf("Couldn't get token user %v", e)
		return nil, e
	}

	sidString, e := user.User.Sid.String()
	if e != nil {
		log.Warnf("Couldn't get user sid string %v", e)
		return nil, e
	}

	return windows.StringToSid(sidString)
}

// Returns true is a user is a member of the Administrator's group
// TODO: Microsoft does not recommend using this function, instead CheckTokenMembership should be used.
// https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-isuseranadmin
func IsUserAnAdmin() (bool, error) {
	shell32 := windows.NewLazySystemDLL("Shell32.dll")
	defer windows.FreeLibrary(windows.Handle(shell32.Handle()))

	isUserAnAdminProc := shell32.NewProc("IsUserAnAdmin")
	ret, _, winError := isUserAnAdminProc.Call()

	if winError != windows.NTE_OP_OK {
		return false, fmt.Errorf("IsUserAnAdmin returns error code %d", winError)
	}
	if ret == 0 {
		return false, nil
	}
	return true, nil
}

// GetDDAgentUserSID returns the SID of the ddagentuser configured at installation time by
// by looking up the user the datadogagent service is configured to execute as.
// unit tests may need to override this method, for example with GetCurrentUserSid, since the Windows
// Services may not be installed.
var GetDDAgentUserSID = func() (*windows.SID, error) {
	mgr, err := OpenSCManager(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("could not connect to SCM: %v", err)
	}
	defer mgr.Disconnect()

	service, err := OpenService(mgr, DatadogAgentServiceName, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return nil, fmt.Errorf("could not open service %s: %v", DatadogAgentServiceName, err)
	}
	defer service.Close()

	config, err := service.Config()
	if err != nil {
		return nil, fmt.Errorf("could not query service config %s: %v", DatadogAgentServiceName, err)
	}

	sid, _, _, err := windows.LookupSID("", config.ServiceStartName)
	return sid, err
}
