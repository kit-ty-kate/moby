package daemon // import "github.com/docker/docker/daemon"

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/containerd/containerd/containers"
	coci "github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/sys"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	daemonconfig "github.com/docker/docker/daemon/config"
	"github.com/docker/docker/oci"
	"github.com/docker/docker/oci/caps"
	"github.com/docker/docker/pkg/idtools"
	volumemounts "github.com/docker/docker/volume/mounts"
	"github.com/moby/sys/mount"
	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/runc/libcontainer/devices"
	"github.com/opencontainers/runc/libcontainer/user"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const inContainerInitPath = "/sbin/" + daemonconfig.DefaultInitBinary

// WithRlimits sets the container's rlimits along with merging the daemon's rlimits
func WithRlimits(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		var rlimits []specs.POSIXRlimit

		// We want to leave the original HostConfig alone so make a copy here
		hostConfig := *c.HostConfig
		// Merge with the daemon defaults
		daemon.mergeUlimits(&hostConfig)
		for _, ul := range hostConfig.Ulimits {
			rlimits = append(rlimits, specs.POSIXRlimit{
				Type: "RLIMIT_" + strings.ToUpper(ul.Name),
				Soft: uint64(ul.Soft),
				Hard: uint64(ul.Hard),
			})
		}

		s.Process.Rlimits = rlimits
		return nil
	}
}

// WithLibnetwork sets the libnetwork hook
func WithLibnetwork(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		/*
		if s.Hooks == nil {
			s.Hooks = &specs.Hooks{}
		}
		s.Hooks.CreateContainer = append(s.Hooks.CreateContainer, specs.Hook{
			Path: "/sbin/ifconfig",
			Args: []string{
				"lo0",
				"inet",
				"127.0.0.1",
				"up",
			},
		})

		for _, network := range c.NetworkSettings.Networks {
			interfacename := "veth" + network.EndpointID[0:7]
			s.Hooks.CreateRuntime = append(s.Hooks.CreateRuntime, specs.Hook{
				Path: "/sbin/ifconfig",
				Args: []string{
					interfacename,
					"vnet",
					c.ID,},})
			s.Hooks.CreateContainer = append(s.Hooks.CreateContainer, specs.Hook{
				Path: "/sbin/ifconfig",
				Args: []string{
					interfacename,
					"inet",
					network.IPAddress+"/"+strconv.Itoa(network.IPPrefixLen),
					"up",},})
			s.Hooks.CreateContainer = append(s.Hooks.CreateContainer, specs.Hook{
				Path: "/sbin/route",
				Args: []string{
					"-4",
					"add",
					"default",
					network.Gateway,},})
		}*/
		return nil
	}
}

// WithOOMScore sets the oom score
func WithOOMScore(score *int) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		s.Process.OOMScoreAdj = score
		return nil
	}
}

// WithSelinux sets the selinux labels
func WithSelinux(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		s.Process.SelinuxLabel = c.GetProcessLabel()
		s.Linux.MountLabel = c.MountLabel
		return nil
	}
}

// WithApparmor sets the apparmor profile
func WithApparmor(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		return nil
	}
}

// WithCapabilities sets the container's capabilties
func WithCapabilities(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		capabilities, err := caps.TweakCapabilities(
			caps.DefaultCapabilities(),
			c.HostConfig.CapAdd,
			c.HostConfig.CapDrop,
			c.HostConfig.Privileged,
		)
		if err != nil {
			return err
		}
		return oci.SetCapabilities(s, capabilities)
	}
}

func resourcePath(c *container.Container, getPath func() (string, error)) (string, error) {
	p, err := getPath()
	if err != nil {
		return "", err
	}
	return c.GetResourcePath(p)
}

func getUser(c *container.Container, username string) (specs.User, error) {
	var usr specs.User
	passwdPath, err := resourcePath(c, user.GetPasswdPath)
	if err != nil {
		return usr, err
	}
	groupPath, err := resourcePath(c, user.GetGroupPath)
	if err != nil {
		return usr, err
	}
	execUser, err := user.GetExecUserPath(username, nil, passwdPath, groupPath)
	if err != nil {
		return usr, err
	}
	usr.UID = uint32(execUser.Uid)
	usr.GID = uint32(execUser.Gid)

	var addGroups []int
	if len(c.HostConfig.GroupAdd) > 0 {
		addGroups, err = user.GetAdditionalGroupsPath(c.HostConfig.GroupAdd, groupPath)
		if err != nil {
			return usr, err
		}
	}
	for _, g := range append(execUser.Sgids, addGroups...) {
		usr.AdditionalGids = append(usr.AdditionalGids, uint32(g))
	}
	return usr, nil
}

func setNamespace(s *specs.Spec, ns specs.LinuxNamespace) {
	for i, n := range s.Linux.Namespaces {
		if n.Type == ns.Type {
			s.Linux.Namespaces[i] = ns
			return
		}
	}
	s.Linux.Namespaces = append(s.Linux.Namespaces, ns)
}

// WithNamespaces sets the container's namespaces
func WithNamespaces(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		userNS := false
		// user
		if c.HostConfig.UsernsMode.IsPrivate() {
			uidMap := daemon.idMapping.UIDs()
			if uidMap != nil {
				userNS = true
				ns := specs.LinuxNamespace{Type: "user"}
				setNamespace(s, ns)
				s.Linux.UIDMappings = specMapping(uidMap)
				s.Linux.GIDMappings = specMapping(daemon.idMapping.GIDs())
			}
		}
		// network
		if !c.Config.NetworkDisabled {
			ns := specs.LinuxNamespace{Type: "network"}
			parts := strings.SplitN(string(c.HostConfig.NetworkMode), ":", 2)
			if parts[0] == "container" {
				nc, err := daemon.getNetworkedContainer(c.ID, c.HostConfig.NetworkMode.ConnectedContainer())
				if err != nil {
					return err
				}
				ns.Path = fmt.Sprintf("/proc/%d/ns/net", nc.State.GetPID())
				if userNS {
					// to share a net namespace, they must also share a user namespace
					nsUser := specs.LinuxNamespace{Type: "user"}
					nsUser.Path = fmt.Sprintf("/proc/%d/ns/user", nc.State.GetPID())
					setNamespace(s, nsUser)
				}
			} else if c.HostConfig.NetworkMode.IsHost() {
				ns.Path = c.NetworkSettings.SandboxKey
			}
			setNamespace(s, ns)
		}

		// ipc
		ipcMode := c.HostConfig.IpcMode
		switch {
		case ipcMode.IsContainer():
			ns := specs.LinuxNamespace{Type: "ipc"}
			ic, err := daemon.getIpcContainer(ipcMode.Container())
			if err != nil {
				return err
			}
			ns.Path = fmt.Sprintf("/proc/%d/ns/ipc", ic.State.GetPID())
			setNamespace(s, ns)
			if userNS {
				// to share an IPC namespace, they must also share a user namespace
				nsUser := specs.LinuxNamespace{Type: "user"}
				nsUser.Path = fmt.Sprintf("/proc/%d/ns/user", ic.State.GetPID())
				setNamespace(s, nsUser)
			}
		case ipcMode.IsHost():
			oci.RemoveNamespace(s, "ipc")
		case ipcMode.IsEmpty():
			// A container was created by an older version of the daemon.
			// The default behavior used to be what is now called "shareable".
			fallthrough
		case ipcMode.IsPrivate(), ipcMode.IsShareable(), ipcMode.IsNone():
			ns := specs.LinuxNamespace{Type: "ipc"}
			setNamespace(s, ns)
		default:
			return fmt.Errorf("Invalid IPC mode: %v", ipcMode)
		}

		// pid
		if c.HostConfig.PidMode.IsContainer() {
			pc, err := daemon.getPidContainer(c)
			if err != nil {
				return err
			}
			ns := specs.LinuxNamespace{
				Type: "pid",
				Path: fmt.Sprintf("/proc/%d/ns/pid", pc.State.GetPID()),
			}
			setNamespace(s, ns)
			if userNS {
				// to share a PID namespace, they must also share a user namespace
				nsUser := specs.LinuxNamespace{
					Type: "user",
					Path: fmt.Sprintf("/proc/%d/ns/user", pc.State.GetPID()),
				}
				setNamespace(s, nsUser)
			}
		} else if c.HostConfig.PidMode.IsHost() {
			oci.RemoveNamespace(s, "pid")
		} else {
			ns := specs.LinuxNamespace{Type: "pid"}
			setNamespace(s, ns)
		}
		// uts
		if c.HostConfig.UTSMode.IsHost() {
			oci.RemoveNamespace(s, "uts")
			s.Hostname = ""
		}

		// cgroup
		if !c.HostConfig.CgroupnsMode.IsEmpty() {
			cgroupNsMode := c.HostConfig.CgroupnsMode
			if !cgroupNsMode.Valid() {
				return fmt.Errorf("invalid cgroup namespace mode: %v", cgroupNsMode)
			}
			if cgroupNsMode.IsPrivate() {
				nsCgroup := specs.LinuxNamespace{Type: "cgroup"}
				setNamespace(s, nsCgroup)
			}
		}

		return nil
	}
}

func specMapping(s []idtools.IDMap) []specs.LinuxIDMapping {
	var ids []specs.LinuxIDMapping
	for _, item := range s {
		ids = append(ids, specs.LinuxIDMapping{
			HostID:      uint32(item.HostID),
			ContainerID: uint32(item.ContainerID),
			Size:        uint32(item.Size),
		})
	}
	return ids
}

// Get the source mount point of directory passed in as argument. Also return
// optional fields.
func getSourceMount(source string) (string, string, error) {
	// Ensure any symlinks are resolved.
	sourcePath, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}

	mi, err := mountinfo.GetMounts(mountinfo.ParentsFilter(sourcePath))
	if err != nil {
		return "", "", err
	}
	if len(mi) < 1 {
		return "", "", fmt.Errorf("Can't find mount point of %s", source)
	}

	// find the longest mount point
	var idx, maxlen int
	for i := range mi {
		if len(mi[i].Mountpoint) > maxlen {
			maxlen = len(mi[i].Mountpoint)
			idx = i
		}
	}
	return mi[idx].Mountpoint, mi[idx].Optional, nil
}

const (
	sharedPropagationOption = "shared:"
	slavePropagationOption  = "master:"
)

// hasMountInfoOption checks if any of the passed any of the given option values
// are set in the passed in option string.
func hasMountInfoOption(opts string, vals ...string) bool {
	for _, opt := range strings.Split(opts, " ") {
		for _, val := range vals {
			if strings.HasPrefix(opt, val) {
				return true
			}
		}
	}
	return false
}

// Ensure mount point on which path is mounted, is shared.
func ensureShared(path string) error {
	sourceMount, optionalOpts, err := getSourceMount(path)
	if err != nil {
		return err
	}
	// Make sure source mount point is shared.
	if !hasMountInfoOption(optionalOpts, sharedPropagationOption) {
		return errors.Errorf("path %s is mounted on %s but it is not a shared mount", path, sourceMount)
	}
	return nil
}

// Ensure mount point on which path is mounted, is either shared or slave.
func ensureSharedOrSlave(path string) error {
	sourceMount, optionalOpts, err := getSourceMount(path)
	if err != nil {
		return err
	}

	if !hasMountInfoOption(optionalOpts, sharedPropagationOption, slavePropagationOption) {
		return errors.Errorf("path %s is mounted on %s but it is not a shared or slave mount", path, sourceMount)
	}
	return nil
}

// Get the set of mount flags that are set on the mount that contains the given
// path and are locked by CL_UNPRIVILEGED. This is necessary to ensure that
// bind-mounting "with options" will not fail with user namespaces, due to
// kernel restrictions that require user namespace mounts to preserve
// CL_UNPRIVILEGED locked flags.
func getUnprivilegedMountFlags(path string) ([]string, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return nil, err
	}

	// The set of keys come from https://github.com/torvalds/linux/blob/v4.13/fs/namespace.c#L1034-L1048.
	unprivilegedFlags := map[uint64]string{
		unix.MNT_RDONLY:     "ro",
		unix.MNT_NOEXEC:     "noexec",
		unix.MNT_NOSUID:     "nosuid",
		unix.MNT_NOATIME:    "noatime",
	}

	var flags []string
	for mask, flag := range unprivilegedFlags {
		if uint64(statfs.Flags)&mask == mask {
			flags = append(flags, flag)
		}
	}

	return flags, nil
}

var (
	mountPropagationMap = map[string]int{
		"private":  mount.PRIVATE,
	}

	mountPropagationReverseMap = map[int]string{
		mount.PRIVATE:  "private",
	}
)

// inSlice tests whether a string is contained in a slice of strings or not.
// Comparison is case sensitive
func inSlice(slice []string, s string) bool {
	for _, ss := range slice {
		if s == ss {
			return true
		}
	}
	return false
}

func isNetworkMount(destination string) bool {
        if destination == "/etc/resolv.conf" {
                return true
        }
        if destination == "/etc/hostname" {
                return true
        }
        if destination == "/etc/hosts" {
                return true
        }
	return false
}


// WithMounts sets the container's mounts
func WithMounts(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) (err error) {
		if err := daemon.setupContainerMountsRoot(c); err != nil {
			return err
		}

		if err := daemon.setupIpcDirs(c); err != nil {
			return err
		}

		defer func() {
			if err != nil {
				daemon.cleanupSecretDir(c)
			}
		}()

		if err := daemon.setupSecretDir(c); err != nil {
			return err
		}

		ms, err := daemon.setupMounts(c)
		if err != nil {
			return err
		}

		if !c.HostConfig.IpcMode.IsPrivate() && !c.HostConfig.IpcMode.IsEmpty() {
			ms = append(ms, c.IpcMounts()...)
		}

		tmpfsMounts, err := c.TmpfsMounts()
		if err != nil {
			return err
		}
		ms = append(ms, tmpfsMounts...)

		secretMounts, err := c.SecretMounts()
		if err != nil {
			return err
		}
		ms = append(ms, secretMounts...)

		sort.Sort(mounts(ms))

		mounts := ms

		userMounts := make(map[string]struct{})
		for _, m := range mounts {
			userMounts[m.Destination] = struct{}{}
		}

		// Copy all mounts from spec to defaultMounts, except for
		//  - mounts overridden by a user supplied mount;
		//  - all mounts under /dev if a user supplied /dev is present;
		//  - /dev/shm, in case IpcMode is none.
		// While at it, also
		//  - set size for /dev/shm from shmsize.
		defaultMounts := s.Mounts[:0]
		_, mountDev := userMounts["/dev"]
		for _, m := range s.Mounts {
			if _, ok := userMounts[m.Destination]; ok {
				// filter out mount overridden by a user supplied mount
				continue
			}
			if mountDev && strings.HasPrefix(m.Destination, "/dev/") {
				// filter out everything under /dev if /dev is user-mounted
				continue
			}

			if m.Destination == "/dev/shm" {
				if c.HostConfig.IpcMode.IsNone() {
					// filter out /dev/shm for "none" IpcMode
					continue
				}
				// set size for /dev/shm mount from spec
				sizeOpt := "size=" + strconv.FormatInt(c.HostConfig.ShmSize, 10)
				m.Options = append(m.Options, sizeOpt)
			}

			defaultMounts = append(defaultMounts, m)
		}

		s.Mounts = defaultMounts
		for _, m := range mounts {
			if m.Source == "tmpfs" {
				data := m.Data
				parser := volumemounts.NewParser("linux")
				options := []string{"noexec", "nosuid", "nodev", string(parser.DefaultPropagationMode())}
				if data != "" {
					options = append(options, strings.Split(data, ",")...)
				}

				merged, err := mount.MergeTmpfsOptions(options)
				if err != nil {
					return err
				}

				s.Mounts = append(s.Mounts, specs.Mount{Destination: m.Destination, Source: m.Source, Type: "tmpfs", Options: merged})
				continue
			} else if isNetworkMount(m.Destination) {
				if s.Hooks == nil {
					s.Hooks = &specs.Hooks{}
				}
				s.Hooks.CreateRuntime = append( s.Hooks.CreateRuntime, specs.Hook{
					Path: "/bin/cp",
					Args: []string{
						m.Source,
						filepath.Join(s.Root.Path, m.Destination)}})
				continue
			}
			mt := specs.Mount{Destination: m.Destination, Source: m.Source, Type: "nullfs"}

			// Determine property of RootPropagation based on volume
			// properties. If a volume is shared, then keep root propagation
			// shared. This should work for slave and private volumes too.
			//
			// For slave volumes, it can be either [r]shared/[r]slave.
			//
			// For private volumes any root propagation value should work.
			pFlag := mountPropagationMap[m.Propagation]
			bindMode := "bind"
			opts := []string{bindMode}
			if !m.Writable {
				opts = append(opts, "ro")
			}
			if pFlag != 0 {
				opts = append(opts, mountPropagationReverseMap[pFlag])
			}

			// If we are using user namespaces, then we must make sure that we
			// don't drop any of the CL_UNPRIVILEGED "locked" flags of the source
			// "mount" when we bind-mount. The reason for this is that at the point
			// when runc sets up the root filesystem, it is already inside a user
			// namespace, and thus cannot change any flags that are locked.
			if daemon.configStore.RemappedRoot != "" || sys.RunningInUserNS() {
				unprivOpts, err := getUnprivilegedMountFlags(m.Source)
				if err != nil {
					return err
				}
				opts = append(opts, unprivOpts...)
			}

			mt.Options = opts
			s.Mounts = append(s.Mounts, mt)
		}

		if s.Root.Readonly {
			for i, m := range s.Mounts {
				switch m.Destination {
				case "/proc", "/dev/pts", "/dev/shm", "/dev/mqueue", "/dev":
					continue
				}
				if _, ok := userMounts[m.Destination]; !ok {
					if !inSlice(m.Options, "ro") {
						s.Mounts[i].Options = append(s.Mounts[i].Options, "ro")
					}
				}
			}
		}

		if c.HostConfig.Privileged {
			// clear readonly for /sys
			for i := range s.Mounts {
				if s.Mounts[i].Destination == "/sys" {
					clearReadOnly(&s.Mounts[i])
				}
			}
			s.Linux.ReadonlyPaths = nil
			s.Linux.MaskedPaths = nil
		}

		return nil

	}
}

// sysctlExists checks if a sysctl exists; runc will error if we add any that do not actually
// exist, so do not add the default ones if running on an old kernel.
func sysctlExists(s string) bool {
	f := filepath.Join("/proc", "sys", strings.Replace(s, ".", "/", -1))
	_, err := os.Stat(f)
	return err == nil
}

// WithCommonOptions sets common docker options
func WithCommonOptions(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		if c.BaseFS == nil {
			return errors.New("populateCommonSpec: BaseFS of container " + c.ID + " is unexpectedly nil")
		}
		linkedEnv, err := daemon.setupLinkedContainers(c)
		if err != nil {
			return err
		}
		s.Root = &specs.Root{
			Path:     c.BaseFS.Path(),
			Readonly: c.HostConfig.ReadonlyRootfs,
		}
		if err := c.SetupWorkingDirectory(daemon.idMapping.RootPair()); err != nil {
			return err
		}
		cwd := c.Config.WorkingDir
		if len(cwd) == 0 {
			cwd = "/"
		}
		s.Process.Args = append([]string{c.Path}, c.Args...)

		// only add the custom init if it is specified and the container is running in its
		// own private pid namespace.  It does not make sense to add if it is running in the
		// host namespace or another container's pid namespace where we already have an init
		if c.HostConfig.PidMode.IsPrivate() {
			if (c.HostConfig.Init != nil && *c.HostConfig.Init) ||
				(c.HostConfig.Init == nil && daemon.configStore.Init) {
				s.Process.Args = append([]string{inContainerInitPath, "--", c.Path}, c.Args...)
				path := daemon.configStore.InitPath
				if path == "" {
					path, err = exec.LookPath(daemonconfig.DefaultInitBinary)
					if err != nil {
						return err
					}
				}
				s.Mounts = append(s.Mounts, specs.Mount{
					Destination: inContainerInitPath,
					Type:        "bind",
					Source:      path,
					Options:     []string{"bind", "ro"},
				})
			}
		}
		s.Process.Cwd = cwd
		s.Process.Env = c.CreateDaemonEnvironment(c.Config.Tty, linkedEnv)
		s.Process.Terminal = c.Config.Tty

		s.Hostname = c.Config.Hostname
		setLinuxDomainname(c, s)

		// Add default sysctls that are generally safe and useful; currently we
		// grant the capabilities to allow these anyway. You can override if
		// you want to restore the original behaviour.
		// We do not set network sysctls if network namespace is host, or if we are
		// joining an existing namespace, only if we create a new net namespace.
		if c.HostConfig.NetworkMode.IsPrivate() {
			// We cannot set up ping socket support in a user namespace
			if !c.HostConfig.UsernsMode.IsPrivate() && sysctlExists("net.ipv4.ping_group_range") {
				// allow unprivileged ICMP echo sockets without CAP_NET_RAW
				s.Linux.Sysctl["net.ipv4.ping_group_range"] = "0 2147483647"
			}
			// allow opening any port less than 1024 without CAP_NET_BIND_SERVICE
			if sysctlExists("net.ipv4.ip_unprivileged_port_start") {
				s.Linux.Sysctl["net.ipv4.ip_unprivileged_port_start"] = "0"
			}
		}

		return nil
	}
}


// WithDevices sets the container's devices
func WithDevices(daemon *Daemon, c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		// Build lists of devices allowed and created within the container.
		var devs []specs.LinuxDevice
		devPermissions := s.Linux.Resources.Devices

		if c.HostConfig.Privileged && !sys.RunningInUserNS() {
			hostDevices, err := devices.HostDevices()
			if err != nil {
				return err
			}
			for _, d := range hostDevices {
				devs = append(devs, oci.Device(d))
			}

			// adding device mappings in privileged containers
			for _, deviceMapping := range c.HostConfig.Devices {
				// issue a warning that custom cgroup permissions are ignored in privileged mode
				if deviceMapping.CgroupPermissions != "rwm" {
					logrus.WithField("container", c.ID).Warnf("custom %s permissions for device %s are ignored in privileged mode", deviceMapping.CgroupPermissions, deviceMapping.PathOnHost)
				}
				// issue a warning that the device path already exists via /dev mounting in privileged mode
				if deviceMapping.PathOnHost == deviceMapping.PathInContainer {
					logrus.WithField("container", c.ID).Warnf("path in container %s already exists in privileged mode", deviceMapping.PathInContainer)
					continue
				}
				d, _, err := oci.DevicesFromPath(deviceMapping.PathOnHost, deviceMapping.PathInContainer, "rwm")
				if err != nil {
					return err
				}
				devs = append(devs, d...)
			}

			devPermissions = []specs.LinuxDeviceCgroup{
				{
					Allow:  true,
					Access: "rwm",
				},
			}
		} else {
			for _, deviceMapping := range c.HostConfig.Devices {
				d, dPermissions, err := oci.DevicesFromPath(deviceMapping.PathOnHost, deviceMapping.PathInContainer, deviceMapping.CgroupPermissions)
				if err != nil {
					return err
				}
				devs = append(devs, d...)
				devPermissions = append(devPermissions, dPermissions...)
			}

			var err error
			devPermissions, err = oci.AppendDevicePermissionsFromCgroupRules(devPermissions, c.HostConfig.DeviceCgroupRules)
			if err != nil {
				return err
			}
		}

		s.Linux.Devices = append(s.Linux.Devices, devs...)
		s.Linux.Resources.Devices = devPermissions

		for _, req := range c.HostConfig.DeviceRequests {
			if err := daemon.handleDevice(req, s); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithResources applies the container resources
func WithResources(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		r := c.HostConfig.Resources
		weightDevices, err := getBlkioWeightDevices(r)
		if err != nil {
			return err
		}
		readBpsDevice, err := getBlkioThrottleDevices(r.BlkioDeviceReadBps)
		if err != nil {
			return err
		}
		writeBpsDevice, err := getBlkioThrottleDevices(r.BlkioDeviceWriteBps)
		if err != nil {
			return err
		}
		readIOpsDevice, err := getBlkioThrottleDevices(r.BlkioDeviceReadIOps)
		if err != nil {
			return err
		}
		writeIOpsDevice, err := getBlkioThrottleDevices(r.BlkioDeviceWriteIOps)
		if err != nil {
			return err
		}

		memoryRes := getMemoryResources(r)
		cpuRes, err := getCPUResources(r)
		if err != nil {
			return err
		}
		blkioWeight := r.BlkioWeight

		specResources := &specs.LinuxResources{
			Memory: memoryRes,
			CPU:    cpuRes,
			BlockIO: &specs.LinuxBlockIO{
				Weight:                  &blkioWeight,
				WeightDevice:            weightDevices,
				ThrottleReadBpsDevice:   readBpsDevice,
				ThrottleWriteBpsDevice:  writeBpsDevice,
				ThrottleReadIOPSDevice:  readIOpsDevice,
				ThrottleWriteIOPSDevice: writeIOpsDevice,
			},
			Pids: getPidsLimit(r),
		}

		if s.Linux.Resources != nil && len(s.Linux.Resources.Devices) > 0 {
			specResources.Devices = s.Linux.Resources.Devices
		}

		s.Linux.Resources = specResources
		return nil
	}
}

// WithSysctls sets the container's sysctls
func WithSysctls(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		// We merge the sysctls injected above with the HostConfig (latter takes
		// precedence for backwards-compatibility reasons).
		for k, v := range c.HostConfig.Sysctls {
			s.Linux.Sysctl[k] = v
		}
		return nil
	}
}

// WithUser sets the container's user
func WithUser(c *container.Container) coci.SpecOpts {
	return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
		var err error
		s.Process.User, err = getUser(c, c.Config.User)
		return err
	}
}

func (daemon *Daemon) createSpec(c *container.Container) (retSpec *specs.Spec, err error) {
	var (
		opts []coci.SpecOpts
		s    = oci.DefaultSpec()
	)
	opts = append(opts,
		WithCommonOptions(daemon, c),
		WithResources(c),
		WithSysctls(c),
		WithDevices(daemon, c),
		WithUser(c),
		WithRlimits(daemon, c),
		WithNamespaces(daemon, c),
		WithCapabilities(c),
		WithSeccomp(daemon, c),
		WithMounts(daemon, c),
		WithLibnetwork(daemon, c),
		WithApparmor(c),
		WithSelinux(c),
		WithOOMScore(&c.HostConfig.OomScoreAdj),
	)
	if c.NoNewPrivileges {
		opts = append(opts, coci.WithNoNewPrivileges)
	}

	// Set the masked and readonly paths with regard to the host config options if they are set.
	if c.HostConfig.MaskedPaths != nil {
		opts = append(opts, coci.WithMaskedPaths(c.HostConfig.MaskedPaths))
	}
	if c.HostConfig.ReadonlyPaths != nil {
		opts = append(opts, coci.WithReadonlyPaths(c.HostConfig.ReadonlyPaths))
	}
	return &s, coci.ApplyOpts(context.Background(), nil, &containers.Container{
		ID: c.ID,
	}, &s, opts...)
}

func clearReadOnly(m *specs.Mount) {
	var opt []string
	for _, o := range m.Options {
		if o != "ro" {
			opt = append(opt, o)
		}
	}
	m.Options = opt
}

// mergeUlimits merge the Ulimits from HostConfig with daemon defaults, and update HostConfig
func (daemon *Daemon) mergeUlimits(c *containertypes.HostConfig) {
	ulimits := c.Ulimits
	// Merge ulimits with daemon defaults
	ulIdx := make(map[string]struct{})
	for _, ul := range ulimits {
		ulIdx[ul.Name] = struct{}{}
	}
	for name, ul := range daemon.configStore.Ulimits {
		if _, exists := ulIdx[name]; !exists {
			ulimits = append(ulimits, ul)
		}
	}
	c.Ulimits = ulimits
}
