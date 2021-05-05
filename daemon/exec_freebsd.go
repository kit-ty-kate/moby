package daemon // import "github.com/docker/docker/daemon"

import (
	"context"

	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/exec"
	"github.com/docker/docker/oci/caps"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func (daemon *Daemon) execSetPlatformOpt(c *container.Container, ec *exec.Config, p *specs.Process) error {
	if len(ec.User) > 0 {
		var err error
		p.User, err = getUser(c, ec.User)
		if err != nil {
			return err
		}
	}
	if ec.Privileged {
		if p.Capabilities == nil {
			p.Capabilities = &specs.LinuxCapabilities{}
		}
		p.Capabilities.Bounding = caps.GetAllCapabilities()
		p.Capabilities.Permitted = p.Capabilities.Bounding
		p.Capabilities.Inheritable = p.Capabilities.Bounding
		p.Capabilities.Effective = p.Capabilities.Bounding
	}
	s := &specs.Spec{Process: p}
	return WithRlimits(daemon, c)(context.Background(), nil, nil, s)
}
