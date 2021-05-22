package osl

import (
	"fmt"
	"net"
	"regexp"
	"sync"
//	"time"
	"os/exec"
	"errors"

	"github.com/docker/libnetwork/types"
	"github.com/sirupsen/logrus"
)

// IfaceOption is a function option type to set interface options
type IfaceOption func(i *nwIface)

type nwIface struct {
	srcName     string
	dstName     string
	master      string
	dstMaster   string
	mac         net.HardwareAddr
	address     *net.IPNet
	addressIPv6 *net.IPNet
	llAddrs     []*net.IPNet
	routes      []*net.IPNet
	bridge      bool
	ns          *networkNamespace
	sync.Mutex
}

func (i *nwIface) SrcName() string {
	i.Lock()
	defer i.Unlock()

	return i.srcName
}

func (i *nwIface) DstName() string {
	i.Lock()
	defer i.Unlock()

	return i.dstName
}

func (i *nwIface) DstMaster() string {
	i.Lock()
	defer i.Unlock()

	return i.dstMaster
}

func (i *nwIface) Bridge() bool {
	i.Lock()
	defer i.Unlock()

	return i.bridge
}

func (i *nwIface) Master() string {
	i.Lock()
	defer i.Unlock()

	return i.master
}

func (i *nwIface) MacAddress() net.HardwareAddr {
	i.Lock()
	defer i.Unlock()

	return types.GetMacCopy(i.mac)
}

func (i *nwIface) Address() *net.IPNet {
	i.Lock()
	defer i.Unlock()

	return types.GetIPNetCopy(i.address)
}

func (i *nwIface) AddressIPv6() *net.IPNet {
	i.Lock()
	defer i.Unlock()

	return types.GetIPNetCopy(i.addressIPv6)
}

func (i *nwIface) LinkLocalAddresses() []*net.IPNet {
	i.Lock()
	defer i.Unlock()

	return i.llAddrs
}

func (i *nwIface) Routes() []*net.IPNet {
	i.Lock()
	defer i.Unlock()

	routes := make([]*net.IPNet, len(i.routes))
	for index, route := range i.routes {
		r := types.GetIPNetCopy(route)
		routes[index] = r
	}

	return routes
}

func (n *networkNamespace) Interfaces() []Interface {
	n.Lock()
	defer n.Unlock()

	ifaces := make([]Interface, len(n.iFaces))

	for i, iface := range n.iFaces {
		ifaces[i] = iface
	}

	return ifaces
}

func (i *nwIface) Remove() error {
	i.Lock()
	n := i.ns
	i.Unlock()

	n.Lock()
	isDefault := n.isDefault
	path := n.path
	n.Unlock()


	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "name", i.SrcName())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to rename %s to %s: %s", i.DstName(), i.SrcName(), string(out))
	}

	// if it is a bridge just delete it.
	if i.Bridge() {
		cmd := exec.Command("/usr/sbin/ifconfig", i.SrcName(), "destroy")
		out, err := cmd.CombinedOutput()
	        if err != nil {
			return fmt.Errorf("Failed to destroy %s", i.SrcName(), string(out))
	        }

	} else if !isDefault {
	        cmd := exec.Command("/sbin/ifconfig", i.DstName(), "-vnet", path)
                out, err := cmd.CombinedOutput()
	        if err != nil {
                    return fmt.Errorf("Failed to remove %s from jail %q: %s", i.DstName(), path, string(out))
	        }
	}

	n.Lock()
	for index, intf := range n.iFaces {
		if intf == i {
			n.iFaces = append(n.iFaces[:index], n.iFaces[index+1:]...)
			break
		}
	}
	n.Unlock()

	n.checkLoV6()

	return nil
}

// Returns the sandbox's side veth interface statistics
func (i *nwIface) Statistics() (*types.InterfaceStatistics, error) {
	return nil, nil
}

func (n *networkNamespace) findDst(srcName string, isBridge bool) string {
	n.Lock()
	defer n.Unlock()

	for _, i := range n.iFaces {
		// The master should match the srcname of the interface and the
		// master interface should be of type bridge, if searching for a bridge type
		if i.SrcName() == srcName && (!isBridge || i.Bridge()) {
			return i.DstName()
		}
	}

	return ""
}

func (n *networkNamespace) AddInterface(srcName, dstPrefix string, options ...IfaceOption) error {
	i := &nwIface{srcName: srcName, dstName: dstPrefix, ns: n}
	i.processInterfaceOptions(options...)

	if i.master != "" {
		i.dstMaster = n.findDst(i.master, true)
		if i.dstMaster == "" {
			return fmt.Errorf("could not find an appropriate master %q for %q",
				i.master, i.srcName)
		}
	}

	n.Lock()
	if n.isDefault {
		i.dstName = i.srcName
	} else {
		i.dstName = fmt.Sprintf("%s%d", dstPrefix, n.nextIfIndex[dstPrefix])
		n.nextIfIndex[dstPrefix]++
	}

	path := n.path
	isDefault := n.isDefault
	n.Unlock()

	// If it is a bridge interface we have to create the bridge inside
	// the namespace so don't try to lookup the interface using srcName
	if i.bridge {
		cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", "bridge", "create", "name", i.srcName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to create bridge %q: %s", i.srcName, string(out))
		}
	} else {
		// Move the network interface to the destination
		// namespace only if the namespace is not a default
		// type
		if !isDefault {
	                cmd := exec.Command("/sbin/ifconfig", i.srcName, "vnet", path)
	                out, err := cmd.CombinedOutput()
	                if err != nil {
	                        return fmt.Errorf("failed to create bridge %q: %s", i.srcName, string(out))
	                }
		}
	}

	// Configure the interface now this is moved in the proper namespace.
	if err := configureInterface(path, i); err != nil {
		// If configuring the device fails move it back to the host namespace
		// and change the name back to the source name. This allows the caller
		// to properly cleanup the interface. Its important especially for
		// interfaces with global attributes, ex: vni id for vxlan interfaces.
		cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "name", i.SrcName())
		out, nerr := cmd.CombinedOutput()
		if nerr != nil {
			logrus.Errorf("renaming interface (%s->%s) failed, %s after config error %v", i.DstName(), i.SrcName(), string(out), err)
		}
		cmd = exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.SrcName(), "-vnet", path)
		out, nerr = cmd.CombinedOutput()
		if nerr != nil {
			logrus.Errorf("moving interface %s to host ns failed, %s, after config error %v", i.SrcName(), string(out), err)
		}
		return err
	}

	// Up the interface.
	/*
	cnt := 0
	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "up")
	var (
		out []byte
		err error
	)
	for out, err = cmd.CombinedOutput(); err != nil && cnt < 3; cnt++ {
		logrus.Debugf("retrying link setup because of: %s", string(out))
		time.Sleep(10 * time.Millisecond)
		cmd = exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "up")
		out, err = cmd.CombinedOutput();
	}
	if err != nil {
		return fmt.Errorf("failed to set link up: %v", err)
	}*/

	// Set the routes on the interface. This can only be done when the interface is up.
	if err := setInterfaceRoutes(path, i); err != nil {
		return fmt.Errorf("error setting interface %q routes to %q: %v", i.DstName(), i.Routes(), err)
	}

	n.Lock()
	n.iFaces = append(n.iFaces, i)
	n.Unlock()

	n.checkLoV6()

	return nil
}

func configureInterface(path string, i *nwIface) error {
	ifaceName := i.DstName()
	ifaceConfigurators := []struct {
		Fn         func(string, *nwIface) error
		ErrMessage string
	}{
		{setInterfaceName, fmt.Sprintf("error renaming interface %q to %q", i.SrcName(), i.DstName())},
		{setInterfaceMAC, fmt.Sprintf("error setting interface %q MAC to %q", ifaceName, i.MacAddress())},
		{setInterfaceIP, fmt.Sprintf("error setting interface %q IP to %v", ifaceName, i.Address())},
		{setInterfaceIPv6, fmt.Sprintf("error setting interface %q IPv6 to %v", ifaceName, i.AddressIPv6())},
		{setInterfaceMaster, fmt.Sprintf("error setting interface %q master to %q", ifaceName, i.DstMaster())},
		{setInterfaceLinkLocalIPs, fmt.Sprintf("error setting interface %q link local IPs to %v", ifaceName, i.LinkLocalAddresses())},
	}

	for _, config := range ifaceConfigurators {
		if err := config.Fn(path, i); err != nil {
			return fmt.Errorf("%s: %v", config.ErrMessage, err)
		}
	}
	return nil
}

func setInterfaceMaster(path string, i *nwIface) error {
	if i.DstMaster() == "" {
		return nil
	}
	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstMaster(), "addm", i.DstName())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func setInterfaceMAC(path string, i *nwIface) error {
	if i.MacAddress() == nil {
		return nil
	}
	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "ether", i.MacAddress().String())
	out, err := cmd.CombinedOutput()
        if err != nil {
                return errors.New(string(out))
        }
	return nil
}

func setInterfaceIP(path string, i *nwIface) error {
	if i.Address() == nil {
		return nil
	}
//	if err := checkRouteConflict(nlh, i.Address(), netlink.FAMILY_V4); err != nil {
//		return err
//	}
        cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "inet", i.Address().String(), "add")
        out, err := cmd.CombinedOutput()
        if err != nil {
                return errors.New(string(out))
        }
	return nil
}

func setInterfaceIPv6(path string, i *nwIface) error {
	if i.AddressIPv6() == nil {
		return nil
	}
//	if err := checkRouteConflict(nlh, i.AddressIPv6(), netlink.FAMILY_V6); err != nil {
//		return err
//	}
	if err := setIPv6(i.ns.path, i.DstName(), true); err != nil {
		return fmt.Errorf("failed to enable ipv6: %v", err)
	}
        cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "inet6", i.AddressIPv6().String(), "add")
        out, err := cmd.CombinedOutput()
        if err != nil {
                return errors.New(string(out))
        }
	return nil
}

func setInterfaceLinkLocalIPs(path string, i *nwIface) error {
	for _, llIP := range i.LinkLocalAddresses() {
	        cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.DstName(), "inet6", llIP.String(), "add")
	        out, err := cmd.CombinedOutput()
	        if err != nil {
	                return errors.New(string(out))
	        }
	}
	return nil
}

func setInterfaceName(path string, i *nwIface) error {
	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", i.SrcName(), "name", i.DstName())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	cmd = exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig")
	out, err = cmd.CombinedOutput()
	fmt.Printf("ifconfig output: %s\n\n\n", string(out))
	return nil
}

func setInterfaceRoutes(path string, i *nwIface) error {
	return nil
}

// In older kernels (like the one in Centos 6.6 distro) sysctl does not have netns support. Therefore
// we cannot gather the statistics from /sys/class/net/<dev>/statistics/<counter> files. Per-netns stats
// are naturally found in /proc/net/dev in kernels which support netns (ifconfig relies on that).
const (
	netStatsFile = "/proc/net/dev"
	base         = "[ ]*%s:([ ]+[0-9]+){16}"
)

func scanInterfaceStats(data, ifName string, i *types.InterfaceStatistics) error {
	var (
		bktStr string
		bkt    uint64
	)

	regex := fmt.Sprintf(base, ifName)
	re := regexp.MustCompile(regex)
	line := re.FindString(data)

	_, err := fmt.Sscanf(line, "%s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
		&bktStr, &i.RxBytes, &i.RxPackets, &i.RxErrors, &i.RxDropped, &bkt, &bkt, &bkt,
		&bkt, &i.TxBytes, &i.TxPackets, &i.TxErrors, &i.TxDropped, &bkt, &bkt, &bkt, &bkt)

	return err
}
/*
func checkRouteConflict(nlh *netlink.Handle, address *net.IPNet, family int) error {
	routes, err := nlh.RouteList(nil, family)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Dst != nil {
			if route.Dst.Contains(address.IP) || address.Contains(route.Dst.IP) {
				return fmt.Errorf("cannot program address %v in sandbox interface because it conflicts with existing route %s",
					address, route)
			}
		}
	}
	return nil
}*/
