// +build !linux,!windows

package libnetwork

import (
	"fmt"
	"net"
)

func (c *controller) cleanupServiceBindings(nid string) {
}

func (c *controller) addServiceBinding(svcName, svcID, nID, eID, containerName string, vip net.IP, ingressPorts []*PortConfig, serviceAliases, taskAliases []string, ip net.IP, method string) error {
	return fmt.Errorf("not supported")
}

func (c *controller) rmServiceBinding(svcName, svcID, nID, eID, containerName string, vip net.IP, ingressPorts []*PortConfig, serviceAliases []string, taskAliases []string, ip net.IP, method string, deleteSvcRecords bool, fullRemove bool) error {
	return fmt.Errorf("not supported")
}

func (c *controller) addContainerNameResolution(nID, eID, containerName string, taskAliases []string, ip net.IP, method string) error {
	return fmt.Errorf("not supported")
}

func (c *controller) delContainerNameResolution(nID, eID, containerName string, taskAliases []string, ip net.IP, method string) error {
	return fmt.Errorf("not supported")
}

func (c *controller) cleanupServiceDiscovery(cleanupNID string) {
}

func (sb *sandbox) populateLoadBalancers(ep *endpoint) {
}

func arrangeIngressFilterRule() {
}

func (c *controller) getLBIndex(sid, nid string, ingressPorts []*PortConfig) int {
	return -1
}

