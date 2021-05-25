package local

import (
	"os"
	"syscall"
	"time"
)

func (v *localVolume) CreatedAt() (time.Time, error) {
	fileInfo, err := os.Stat(v.path)
	if err != nil {
		return time.Time{}, err
	}
	sec, nsec := fileInfo.Sys().(*syscall.Stat_t).Ctimespec.Unix()
	return time.Unix(sec, nsec), nil
}
