package types

import (
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// Summary is not used on FreeBSD
type Summary struct{}

// Stats holds metrics properties as returned by containerd
type Stats struct {}

// InterfaceToStats returns a stats object from the platform-specific interface.
func InterfaceToStats(read time.Time, v interface{}) *Stats {
	return &Stats{}
}

// StateInfo contains description about the new state container has entered.
type StateInfo struct {
	//CommonStateInfo

	// Platform specific StateInfo
	OOMKilled bool
	ExitCode int
}

// Resources defines updatable container resource values. TODO: it must match containerd upcoming API
type Resources specs.LinuxResources

// Checkpoints contains the details of a checkpoint
type Checkpoints struct{}
