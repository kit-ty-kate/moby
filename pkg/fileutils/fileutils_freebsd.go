// +build freebsd

package fileutils // import "github.com/docker/docker/pkg/fileutils"

import (
	"fmt"
	"io/ioutil"

	"github.com/sirupsen/logrus"
)

// GetTotalUsedFds Returns the number of used File Descriptors by
// reading it via /proc filesystem.
func GetTotalUsedFds() int {
	if fds, err := ioutil.ReadDir(fmt.Sprintf("/dev/fd")); err != nil {
		logrus.Errorf("Error opening /dev/fd: %s", err)
	} else {
		return len(fds)
	}
	return -1
}
