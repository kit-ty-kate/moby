package osl

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"errors"

	"github.com/docker/libnetwork/osl/kernel"
	"github.com/docker/libnetwork/types"
	"github.com/sirupsen/logrus"
	"github.com/gizahNL/gojail"
)

var (
	once               sync.Once
	garbagePathMap     = make(map[string]bool)
	gpmLock            sync.Mutex
	gpmWg              sync.WaitGroup
	gpmCleanupPeriod   = 60 * time.Second
	gpmChan            = make(chan chan struct{})
	loadBalancerConfig = map[string]*kernel.OSValue{
		// disables any special handling on port reuse of existing IPVS connection table entries
		// more info: https://github.com/torvalds/linux/blob/master/Documentation/networking/ipvs-sysctl.txt#L25:1
		"net.ipv4.vs.conn_reuse_mode": {Value: "0", CheckFn: nil},
		// expires connection from the IPVS connection table when the backend is not available
		// more info: https://github.com/torvalds/linux/blob/master/Documentation/networking/ipvs-sysctl.txt#L126:1
		"net.ipv4.vs.expire_nodest_conn": {Value: "1", CheckFn: nil},
		// expires persistent connections to destination servers with weights set to 0
		// more info: https://github.com/torvalds/linux/blob/master/Documentation/networking/ipvs-sysctl.txt#L144:1
		"net.ipv4.vs.expire_quiescent_template": {Value: "1", CheckFn: nil},
	}
)

// The networkNamespace type is the linux implementation of the Sandbox
// interface. It represents a linux network namespace, and moves an interface
// into it when called on method AddInterface or sets the gateway etc.
type networkNamespace struct {
	path         string
	iFaces       []*nwIface
	gw           net.IP
	gwv6         net.IP
	staticRoutes []*types.StaticRoute
	neighbors    []*neigh
	nextIfIndex  map[string]int
	isDefault    bool
	loV6Enabled  bool
	jail	     gojail.Jail
	sync.Mutex
}

// SetBasePath sets the base url prefix for the ns path
func SetBasePath(path string) {
}

func removeUnusedPaths() {
	gpmLock.Lock()
	period := gpmCleanupPeriod
	gpmLock.Unlock()

	ticker := time.NewTicker(period)
	for {
		var (
			gc   chan struct{}
			gcOk bool
		)

		select {
		case <-ticker.C:
		case gc, gcOk = <-gpmChan:
		}

		gpmLock.Lock()
		pathList := make([]string, 0, len(garbagePathMap))
		for path := range garbagePathMap {
			pathList = append(pathList, path)
		}
		garbagePathMap = make(map[string]bool)
		gpmWg.Add(1)
		gpmLock.Unlock()

		for _, path := range pathList {
			os.Remove(path)
		}

		gpmWg.Done()
		if gcOk {
			close(gc)
		}
	}
}

func addToGarbagePaths(path string) {
	gpmLock.Lock()
	garbagePathMap[path] = true
	gpmLock.Unlock()
}

func removeFromGarbagePaths(path string) {
	gpmLock.Lock()
	delete(garbagePathMap, path)
	gpmLock.Unlock()
}

// GC triggers garbage collection of namespace path right away
// and waits for it.
func GC() {
	gpmLock.Lock()
	if len(garbagePathMap) == 0 {
		// No need for GC if map is empty
		gpmLock.Unlock()
		return
	}
	gpmLock.Unlock()

	// if content exists in the garbage paths
	// we can trigger GC to run, providing a
	// channel to be notified on completion
	waitGC := make(chan struct{})
	gpmChan <- waitGC
	// wait for GC completion
	<-waitGC
}

// GenerateKey generates a sandbox key based on the passed
// container id.
func GenerateKey(containerID string) string {
	maxLen := 12
	// Read sandbox key from host for overlay

	if len(containerID) < maxLen {
		maxLen = len(containerID)
	}

	return containerID[:maxLen]
}

// NewSandbox provides a new sandbox instance created in an os specific way
// provided a key which uniquely identifies the sandbox
func NewSandbox(key string, osCreate, isRestore bool) (Sandbox, error) {
	var (
		err error
		jail gojail.Jail
	)
	if !isRestore {
		jail, err = createNetworkNamespace(key)
		if err != nil {
			return nil, err
		}
	} else {
		once.Do(func() {go removeUnusedPaths()})
		jail, err = gojail.JailGetByName(key)
	}

	n := &networkNamespace{path: key, isDefault: !osCreate, jail: jail, nextIfIndex: make(map[string]int)}

	// In live-restore mode, IPV6 entries are getting cleaned up due to below code
	// We should retain IPV6 configurations in live-restore mode when Docker Daemon
	// comes back. It should work as it is on other cases
	// As starting point, disable IPv6 on all interfaces
	if !isRestore && !n.isDefault {
		err = setIPv6(n.path, "all", false)
		if err != nil {
			logrus.Warnf("Failed to disable IPv6 on all interfaces on network namespace %q: %v", n.path, err)
		}
	}

	if err = n.loopbackUp(); err != nil {
		return nil, err
	}

	return n, nil
}

func (n *networkNamespace) InterfaceOptions() IfaceOptionSetter {
	return n
}

func (n *networkNamespace) NeighborOptions() NeighborOptionSetter {
	return n
}

// GetSandboxForExternalKey returns sandbox object for the supplied path
func GetSandboxForExternalKey(basePath string, key string) (Sandbox, error) {
	fmt.Printf("GETSANDBOXFOREXTERNALKEY\n\n")
	jail, err := createNetworkNamespace(key)
	if err != nil {
		return nil, err
	}

	n := &networkNamespace{path: key, jail:jail, nextIfIndex: make(map[string]int)}

	if err = n.loopbackUp(); err != nil {
		return nil, err
	}

	return n, nil
}

func createNetworkNamespace(path string) (gojail.Jail,error) {
	if err := createNamespaceFile(path); err != nil {
		return nil, err
	}
        jailconf := make(map[string]interface{})
        jailconf["name"] = path
        //jailconf["allow.set_hostname"] = true
        //jailconf["allow.sysvipc"] = true
        //jailconf["allow.raw_sockets"] = true
        jailconf["vnet"] = int32(1)
        jailconf["persist"] = true
        jailconf["path"] = "/"
        //jailconf["linux"] = "inherit"
        jail, err := gojail.JailCreate(jailconf)
        if err != nil {
                return nil, fmt.Errorf("Failed to create network jail %q: %v", path, err)
        }
	return jail, nil
}

func createNamespaceFile(path string) (err error) {
	once.Do(func() {go removeUnusedPaths()})
	// Remove it from garbage collection list if present
	removeFromGarbagePaths(path)

	// wait for garbage collection to complete if it is in progress
	// before trying to create the file.
	gpmWg.Wait()

	return err
}

func (n *networkNamespace) loopbackUp() error {
        n.Lock()
	path := n.path
        defer n.Unlock()

	cmd := exec.Command("/usr/sbin/jexec", path, "/sbin/ifconfig", "lo0", "inet", "127.0.0.1", "up")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(string(out))
	}
	return nil
}

func (n *networkNamespace) GetLoopbackIfaceName() string {
	return "lo0"
}

func (n *networkNamespace) AddAliasIP(ifName string, ip *net.IPNet) error {
	return nil
}

func (n *networkNamespace) RemoveAliasIP(ifName string, ip *net.IPNet) error {
	return nil
}

//not implemented
func (n *networkNamespace) DisableARPForVIP(srcName string) (Err error) {
	return nil
}

//not implemented
func (n *networkNamespace) InvokeFunc(f func()) error {
	return nil
}

// InitOSContext initializes OS context while configuring network resources
func InitOSContext() func() {
	return func() { }
}

func (n *networkNamespace) nsPath() string {
	n.Lock()
	defer n.Unlock()

	return n.path
}

func (n *networkNamespace) Info() Info {
	return n
}

func (n *networkNamespace) Key() string {
	return n.path
}

func (n *networkNamespace) Destroy() error {
	//This will also remove all children!
	if err := n.jail.Destroy(); err != nil {
		return err
	}

	// Stash it into the garbage collection list
	addToGarbagePaths(n.path)
	return nil
}

// Restore restore the network namespace
func (n *networkNamespace) Restore(ifsopt map[string][]IfaceOption, routes []*types.StaticRoute, gw net.IP, gw6 net.IP) error {
	// restore interfaces
	for name, opts := range ifsopt {
		if !strings.Contains(name, "+") {
			return fmt.Errorf("wrong iface name in restore osl sandbox interface: %s", name)
		}
		seps := strings.Split(name, "+")
		srcName := seps[0]
		dstPrefix := seps[1]
		i := &nwIface{srcName: srcName, dstName: dstPrefix, ns: n}
		i.processInterfaceOptions(opts...)
		if i.master != "" {
			i.dstMaster = n.findDst(i.master, true)
			if i.dstMaster == "" {
				return fmt.Errorf("could not find an appropriate master %q for %q",
					i.master, i.srcName)
			}
		}
		if n.isDefault {
			i.dstName = i.srcName
		} else {
			//TODO
		}
	}

	// restore routes
	for _, r := range routes {
		n.Lock()
		n.staticRoutes = append(n.staticRoutes, r)
		n.Unlock()
	}

	// restore gateway
	if len(gw) > 0 {
		n.Lock()
		n.gw = gw
		n.Unlock()
	}

	if len(gw6) > 0 {
		n.Lock()
		n.gwv6 = gw6
		n.Unlock()
	}

	return nil
}

// Checks whether IPv6 needs to be enabled/disabled on the loopback interface
func (n *networkNamespace) checkLoV6() {
	var (
		enable = false
		action = "disable"
	)

	n.Lock()
	for _, iface := range n.iFaces {
		if iface.AddressIPv6() != nil {
			enable = true
			action = "enable"
			break
		}
	}
	n.Unlock()

	if n.loV6Enabled == enable {
		return
	}

	if err := setIPv6(n.path, "lo0", enable); err != nil {
		logrus.Warnf("Failed to %s IPv6 on loopback interface on network namespace %q: %v", action, n.path, err)
	}

	n.loV6Enabled = enable
}

func setIPv6(path, iface string, enable bool) error {
	return nil
}

// ApplyOSTweaks applies linux configs on the sandbox
func (n *networkNamespace) ApplyOSTweaks(types []SandboxType) {
	//not implemented
}
