package netutils

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
        "github.com/docker/libnetwork/ipamutils"
	"github.com/docker/libnetwork/types"
	"github.com/pkg/errors"
)

// ElectInterfaceAddresses looks for an interface on the OS with the specified name
// and returns returns all its IPv4 and IPv6 addresses in CIDR notation.
// If a failure in retrieving the addresses or no IPv4 address is found, an error is returned.
// If the interface does not exist, it chooses from a predefined
// list the first IPv4 address which does not conflict with other
// interfaces on the system.
func ElectInterfaceAddresses(name string) ([]*net.IPNet, []*net.IPNet, error) {
        var (
                v4Nets []*net.IPNet
                v6Nets []*net.IPNet
        )
	iface, _ := net.InterfaceByName(name)
	if iface != nil {
		addrs, err := iface.Addrs()
		if err != nil && len(addrs) > 0 {
			for _, addr := range addrs {
				switch v:= addr.(type) {
				case *net.IPNet:
					if  v.IP.To4() != nil {
						v4Nets = append(v4Nets, v)
					} else {
						v6Nets = append(v6Nets, v)
					}
				}
			}
		}
	}
	if len(v4Nets) == 0 {
	        // Choose from predefined local scope networks
        	v4Net, err := FindAvailableNetwork(ipamutils.PredefinedLocalScopeDefaultNetworks)
	        if err != nil {
        	    return nil, nil, errors.Wrapf(err, "PredefinedLocalScopeDefaultNetworks List: %+v",
                	             ipamutils.PredefinedLocalScopeDefaultNetworks)
	        }
        	v4Nets = append(v4Nets, v4Net)
	}
	return v4Nets, v6Nets, nil
}

// FindAvailableNetwork returns a network from the passed list which does not
// overlap with existing interfaces in the system
func FindAvailableNetwork(list []*net.IPNet) (*net.IPNet, error) {
	for _, avail := range list {
		cidr := strings.Split(avail.String(), "/")
		ipitems := strings.Split(cidr[0], ".")
		ip := ipitems[0] + "." +
		      ipitems[1] + "." +
		      ipitems[2] + "." + "1"

		out, err := exec.Command("/sbin/route", "get", ip).Output()
		if err != nil {
			fmt.Println("failed to run route get command")
			return nil, err
		}
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			s := strings.Split(string(l), ":")
			if len(s) == 2 {
				k, v := s[0], strings.TrimSpace(s[1])
				if k == "destination" {
					if v == "default" {
						return avail, nil
					}
					break
				}
			}
		}
	}
	return nil, fmt.Errorf("no available network")
	//types.NotImplementedErrorf("not supported on freebsd")
}

// GenerateIfaceName returns an interface name using the passed in
// prefix and the length of random bytes. The api ensures that the
// there are is no interface which exists with that name.
func GenerateIfaceName(prefix string, len int) (string, error) {
        for i := 0; i < 3; i++ {
                name, err := GenerateRandomName(prefix, len)
                if err != nil {
                        continue
                }
                _, err = net.InterfaceByName(name)
                if err != nil {
                        if strings.Contains(err.Error(), "no such") {
                                return name, nil
                        }
                        return "", err
                }
        }
        return "", types.InternalErrorf("could not generate interface name")
}

// GenerateIfaceName returns an interface name using the passed in
// prefix and the length of random bytes. The api ensures that the
// there are is no interface which exists with that name.
func GenerateIfaceNameFromEID(prefix string, maxlen int, eid string) (string, error) {
	// Generate a name for what will be the sandbox side pipe interface
        suffixlen := len(eid)
        if suffixlen > maxlen {
                suffixlen = maxlen
        }
	name := prefix + eid[0:suffixlen]
	_, err := net.InterfaceByName(name)
        if err != nil {
            if strings.Contains(err.Error(), "no such") {
                return name, nil
             }
             return "", err
        }
        return "", types.InternalErrorf("could not generate interface name")
}

