// +build !windows

package oci

import (
	"context"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/docker/docker/pkg/idtools"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/entitlements/security"
	"github.com/moby/buildkit/util/system"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux/label"
)

func generateMountOpts(resolvConf, hostsFile string) ([]oci.SpecOpts, error) {
	return []oci.SpecOpts{
		// https://github.com/moby/buildkit/issues/429
		withRemovedMount("/run"),
		withROBind(resolvConf, "/etc/resolv.conf"),
		withROBind(hostsFile, "/etc/hosts"),
		withCGroup(),
	}, nil
}

// generateSecurityOpts may affect mounts, so must be called after generateMountOpts
func generateSecurityOpts(mode pb.SecurityMode, apparmorProfile string) (opts []oci.SpecOpts, _ error) {
	switch mode {
	case pb.SecurityMode_INSECURE:
		return []oci.SpecOpts{
			security.WithInsecureSpec(),
			oci.WithWriteableCgroupfs,
			oci.WithWriteableSysfs,
			func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
				var err error
				s.Process.SelinuxLabel, s.Linux.MountLabel, err = label.InitLabels([]string{"disable"})
				return err
			},
		}, nil
	case pb.SecurityMode_SANDBOX:
		if system.SeccompSupported() {
			opts = append(opts, withDefaultProfile())
		}
		if apparmorProfile != "" {
			opts = append(opts, oci.WithApparmorProfile(apparmorProfile))
		}
		opts = append(opts, func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
			var err error
			s.Process.SelinuxLabel, s.Linux.MountLabel, err = label.InitLabels(nil)
			return err
		})
		return opts, nil
	}
	return nil, nil
}

// generateProcessModeOpts may affect mounts, so must be called after generateMountOpts
func generateProcessModeOpts(mode ProcessMode) ([]oci.SpecOpts, error) {
	if mode == NoProcessSandbox {
		return []oci.SpecOpts{
			oci.WithHostNamespace(specs.PIDNamespace),
			withBoundProc(),
		}, nil
		// TODO(AkihiroSuda): Configure seccomp to disable ptrace (and prctl?) explicitly
	}
	return nil, nil
}

func generateIDmapOpts(idmap *idtools.IdentityMapping) ([]oci.SpecOpts, error) {
	if idmap == nil {
		return nil, nil
	}
	return []oci.SpecOpts{
		oci.WithUserNamespace(specMapping(idmap.UIDs()), specMapping(idmap.GIDs())),
	}, nil
}

