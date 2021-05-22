package osl

import (
	"bytes"
	"fmt"
	"net"
)

// NeighborSearchError indicates that the neighbor is already present
type NeighborSearchError struct {
	ip      net.IP
	mac     net.HardwareAddr
	present bool
}

func (n NeighborSearchError) Error() string {
	return fmt.Sprintf("Search neighbor failed for IP %v, mac %v, present in db:%t", n.ip, n.mac, n.present)
}

// NeighOption is a function option type to set interface options
type NeighOption func(nh *neigh)

type neigh struct {
	dstIP    net.IP
	dstMac   net.HardwareAddr
	linkName string
	linkDst  string
	family   int
}

func (n *networkNamespace) findNeighbor(dstIP net.IP, dstMac net.HardwareAddr) *neigh {
	n.Lock()
	defer n.Unlock()

	for _, nh := range n.neighbors {
		if nh.dstIP.Equal(dstIP) && bytes.Equal(nh.dstMac, dstMac) {
			return nh
		}
	}

	return nil
}

func (n *networkNamespace) DeleteNeighbor(dstIP net.IP, dstMac net.HardwareAddr, osDelete bool) error {
	return nil
}

func (n *networkNamespace) AddNeighbor(dstIP net.IP, dstMac net.HardwareAddr, force bool, options ...NeighOption) error {
	return nil
}
