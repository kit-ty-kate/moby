// +build !linux,!darwin,!windows

package cnmallocator

import (
	"github.com/docker/swarmkit/manager/allocator/networkallocator"
)

var initializers = []initializer{}

// PredefinedNetworks returns the list of predefined network structures
func PredefinedNetworks() []networkallocator.PredefinedNetworkData {
	return nil
}
