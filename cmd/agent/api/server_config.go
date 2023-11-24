// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	gorilla "github.com/gorilla/mux"

	"github.com/DataDog/datadog-agent/pkg/config"
)

var ipcConfigListener net.Listener

func startIPCServer(ipcConfigHostPort string, tlsConfig *tls.Config) (err error) {
	ipcConfigListener, err = getListener(ipcConfigHostPort)
	if err != nil {
		return err
	}

	configEndpointHandler := func(w http.ResponseWriter, r *http.Request) {
		vars := gorilla.Vars(r)

		body, err := getConfigMarshalled(vars["path"])
		if err != nil {
			body, _ := json.Marshal(map[string]string{"error": err.Error()})
			http.Error(w, string(body), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	}

	configEndpointMux := gorilla.NewRouter()
	configEndpointMux.HandleFunc("/", configEndpointHandler).Methods("GET")
	configEndpointMux.HandleFunc("/.", configEndpointHandler).Methods("GET")
	configEndpointMux.HandleFunc("/{path}", configEndpointHandler).Methods("GET")
	configEndpointMux.Use(validateToken)

	ipcMux := http.NewServeMux()
	ipcMux.Handle(
		"/config/",
		http.StripPrefix("/config", configEndpointMux))

	ipcConfigServer := &http.Server{
		Addr:      ipcConfigHostPort,
		Handler:   http.TimeoutHandler(ipcMux, time.Duration(config.Datadog.GetInt64("server_timeout"))*time.Second, "timeout"),
		TLSConfig: tlsConfig,
	}

	startServer(ipcConfigListener, ipcConfigServer, "Config API server")

	return nil
}

func getConfigMarshalled(path string) ([]byte, error) {
	if path == "." {
		path = ""
	}

	var data interface{}
	if path == "" {
		data = config.Datadog.AllSettings()
	} else {
		data = config.Datadog.Get(path)
	}

	if data == nil {
		return nil, fmt.Errorf("no runtime setting found for %s", path)
	}

	return json.Marshal(map[string]interface{}{
		"request": path,
		"value":   data,
	})
}
