package bridge

import (
	"fmt"
	"os/exec"
	"net"
)

// SetupDevice create a new bridge interface/
func setupDevice(config *networkConfiguration, i *bridgeInterface) error {
	var err error
	// We only attempt to create the bridge when the requested device name is
	// the default one.
	if config.BridgeName != DefaultBridgeName && config.DefaultBridge {
		return NonDefaultBridgeExistError(config.BridgeName)
	}

	err = exec.Command("/sbin/ifconfig", "bridge", "create", "name", config.BridgeName).Run()
	if err != nil {
            return fmt.Errorf("failed to create bridge %s: %v", config.BridgeName,  err)
	}
	i.Link, err = net.InterfaceByName(config.BridgeName)
	if err != nil {
		return err
	}
	return nil
}

func setupDefaultSysctl(config *networkConfiguration, i *bridgeInterface) error {
	return nil
}

// SetupDeviceUp ups the given bridge interface.
func setupDeviceUp(config *networkConfiguration, i *bridgeInterface) error {
	return nil
}
