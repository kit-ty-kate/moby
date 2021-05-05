package main

import (
	"github.com/docker/docker/libcontainerd/supervisor"
)

// preNotifyReady sends a message to the host when the API is active, but before the daemon is
func preNotifyReady() {
}

// notifyReady sends a message to the host when the server is ready to be used
func notifyReady() {
}

// notifyStopping sends a message to the host when the server is shutting down
func notifyStopping() {
}

func (cli *DaemonCli) getPlatformContainerdDaemonOpts() ([]supervisor.DaemonOpt, error) {
        return nil, nil
}

