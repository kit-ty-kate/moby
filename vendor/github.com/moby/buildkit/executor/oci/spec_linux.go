// +build !windows

package oci

import (
	"context"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/docker/docker/profiles/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)


// withDefaultProfile sets the default seccomp profile to the spec.
// Note: must follow the setting of process capabilities
func withDefaultProfile() oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *specs.Spec) error {
		var err error
		s.Linux.Seccomp, err = seccomp.GetDefaultProfile(s)
		return err
	}
}
