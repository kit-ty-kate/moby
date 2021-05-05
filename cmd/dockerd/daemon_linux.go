package main
import (
	"github.com/containerd/containerd/runtime/v1/linux"
	"github.com/docker/docker/libcontainerd/supervisor"
)
import systemdDaemon "github.com/coreos/go-systemd/v22/daemon"

// preNotifyReady sends a message to the host when the API is active, but before the daemon is
func preNotifyReady() {
}

// notifyReady sends a message to the host when the server is ready to be used
func notifyReady() {
	// Tell the init daemon we are accepting requests
	go systemdDaemon.SdNotify(false, systemdDaemon.SdNotifyReady)
}

// notifyStopping sends a message to the host when the server is shutting down
func notifyStopping() {
	go systemdDaemon.SdNotify(false, systemdDaemon.SdNotifyStopping)
}

func (cli *DaemonCli) getPlatformContainerdDaemonOpts() ([]supervisor.DaemonOpt, error) {
        opts := []supervisor.DaemonOpt{
                supervisor.WithOOMScore(cli.Config.OOMScoreAdjust),
                supervisor.WithPlugin("linux", &linux.Config{
                        Shim:        daemon.DefaultShimBinary,
                        Runtime:     daemon.DefaultRuntimeBinary,
                        RuntimeRoot: filepath.Join(cli.Config.Root, "runc"),
                        ShimDebug:   cli.Config.Debug,
                }),
        }

        return opts, nil
}

