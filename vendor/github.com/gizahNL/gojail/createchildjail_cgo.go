// +build cgo

package gojail

/*
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/jail.h>

#define JAIL_ERRMSGLEN  1024

int create_jail_in_child(int parent, int pipefd, char* errbuf, struct iovec *iov, u_int niov)
{
	pid_t pid = fork();
	int res;
	if (pid == 0) {
		res = jail_attach(parent);
		if (res != 0) {
			_exit(EXIT_FAILURE);
		}
		res = jail_set(iov, niov, JAIL_CREATE);
		if (res == -1) {
			write(pipefd, errbuf, JAIL_ERRMSGLEN);
			_exit(EXIT_FAILURE);
		}
		write(pipefd, &res, sizeof(res));
		_exit(EXIT_SUCCESS);
	} else if (pid > 0) {
		pid = waitpid(pid, &res, 0);
		if (WIFEXITED(res)) {
			return WEXITSTATUS(res);
		}
		return 0;
	}
	return EXIT_FAILURE;
}
*/
import "C"

import (
	"errors"
	"os"
	"unsafe"
)

func (j *jail) CreateChildJail(parameters map[string]interface{}) (Jail, error) {
	name, err := jailParametersGetName(parameters)
	if err != nil {
		return nil, err
	}

	iovecs, err := JailParseParametersToIovec(parameters)
	if err != nil {
		return nil, err
	}

	err = checkAndIncreaseChildMax(j.jailID)
	if err != nil {
		return nil, err
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	errbuf, erriov := makeErrorIov()

	iovecs = append(iovecs, erriov...)
	iov := (*C.struct_iovec)(unsafe.Pointer(&iovecs[0]))
	result := C.create_jail_in_child(C.int(j.jailID), C.int(writer.Fd()), (*C.char)(unsafe.Pointer(&errbuf[0])), iov, C.uint(len(iovecs)))
	if result != 0 {
		reader.Read(errbuf)
		return nil, errors.New(string(errbuf))
	}
	jidbuf := make([]byte, 4)
	reader.Read(jidbuf)
	jid := (*JailID)(unsafe.Pointer(&jidbuf[0]))
	return &jail{
		jailID:   *jid,
		jailName: name,
	}, nil
}

func checkAndIncreaseChildMax(jid JailID) error {
	var childrenMax, childrenCur int32
	getparam := make(map[string]interface{})
	getparam["jid"] = jid
	getparam["children.max"] = &childrenMax
	getparam["children.cur"] = &childrenCur

	getIovecs, err := JailParseParametersToIovec(getparam)
	if err != nil {
		return err
	}

	_, err = JailGet(getIovecs, 0)
	if err != nil {
		return err
	}

	if childrenCur >= childrenMax {
		setparam := make(map[string]interface{})
		setparam["jid"] = jid
		setparam["children.max"] = childrenMax + 1

		setIovecs, err := JailParseParametersToIovec(setparam)
		if err != nil {
			return err
		}
		_, err = JailSet(setIovecs, JailFlagUpdate)
		return err
	}
	return nil
}
