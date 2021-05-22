package osl

import (
	"net"
	"os/exec"
	"errors"

	"github.com/docker/libnetwork/types"
)

func (n *networkNamespace) Gateway() net.IP {
	n.Lock()
	defer n.Unlock()

	return n.gw
}

func (n *networkNamespace) GatewayIPv6() net.IP {
	n.Lock()
	defer n.Unlock()

	return n.gwv6
}

func (n *networkNamespace) StaticRoutes() []*types.StaticRoute {
	n.Lock()
	defer n.Unlock()

	routes := make([]*types.StaticRoute, len(n.staticRoutes))
	for i, route := range n.staticRoutes {
		r := route.GetCopy()
		routes[i] = r
	}

	return routes
}

func (n *networkNamespace) setGateway(gw net.IP) {
	n.Lock()
	n.gw = gw
	n.Unlock()
}

func (n *networkNamespace) setGatewayIPv6(gwv6 net.IP) {
	n.Lock()
	n.gwv6 = gwv6
	n.Unlock()
}

func (n *networkNamespace) SetGateway(gw net.IP) error {
	// Silently return if the gateway is empty
	if len(gw) == 0 {
		return nil
	}

	err := n.programGateway(gw, true)
	if err == nil {
		n.setGateway(gw)
	}

	return err
}

func (n *networkNamespace) UnsetGateway() error {
	gw := n.Gateway()

	// Silently return if the gateway is empty
	if len(gw) == 0 {
		return nil
	}
	err := n.programGateway(gw, false)
	if err == nil {
		n.setGateway(net.IP{})
	}

	return err
}

func (n *networkNamespace) programGateway(gw net.IP, isAdd bool) error {
        n.Lock()
	path := n.path
        n.Unlock()

	action := "delete"
	if isAdd {
		action = "add"
	}
	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/route", action, "default", gw.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

// Program a route in to the namespace routing table.
func (n *networkNamespace) programRoute(path string, dest *net.IPNet, nh net.IP) error {
        cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/route", "add", dest.String(), nh.String())
        out, err := cmd.CombinedOutput()
        if err != nil {
                return errors.New(string(out))
        }
        return nil

}

// Delete a route from the namespace routing table.
func (n *networkNamespace) removeRoute(path string, dest *net.IPNet, nh net.IP) error {
        cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/route", "delete", dest.String())
        out, err := cmd.CombinedOutput()
        if err != nil {
                return errors.New(string(out))
        }
        return nil
}

func (n *networkNamespace) SetGatewayIPv6(gwv6 net.IP) error {
	// Silently return if the gateway is empty
	if len(gwv6) == 0 {
		return nil
	}

	err := n.programGateway(gwv6, true)
	if err == nil {
		n.setGatewayIPv6(gwv6)
	}

	return err
}

func (n *networkNamespace) UnsetGatewayIPv6() error {
	gwv6 := n.GatewayIPv6()

	// Silently return if the gateway is empty
	if len(gwv6) == 0 {
		return nil
	}

	err := n.programGateway(gwv6, false)
	if err == nil {
		n.Lock()
		n.gwv6 = net.IP{}
		n.Unlock()
	}

	return err
}

func (n *networkNamespace) AddStaticRoute(r *types.StaticRoute) error {
	err := n.programRoute(n.nsPath(), r.Destination, r.NextHop)
	if err == nil {
		n.Lock()
		n.staticRoutes = append(n.staticRoutes, r)
		n.Unlock()
	}
	return err
}

func (n *networkNamespace) RemoveStaticRoute(r *types.StaticRoute) error {

	err := n.removeRoute(n.nsPath(), r.Destination, r.NextHop)
	if err == nil {
		n.Lock()
		lastIndex := len(n.staticRoutes) - 1
		for i, v := range n.staticRoutes {
			if v == r {
				// Overwrite the route we're removing with the last element
				n.staticRoutes[i] = n.staticRoutes[lastIndex]
				// Shorten the slice to trim the extra element
				n.staticRoutes = n.staticRoutes[:lastIndex]
				break
			}
		}
		n.Unlock()
	}
	return err
}
