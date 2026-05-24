package systemd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

const listenFdsStart = 3

type ActivatedListener struct {
	Listener net.Listener
	Name     string
}

func Listeners() ([]ActivatedListener, error) {
	pidRaw := os.Getenv("LISTEN_PID")
	fdsRaw := os.Getenv("LISTEN_FDS")
	if pidRaw == "" || fdsRaw == "" {
		return nil, errors.New("systemd socket activation env is missing")
	}

	pid, err := strconv.Atoi(pidRaw)
	if err != nil {
		return nil, fmt.Errorf("parse LISTEN_PID: %w", err)
	}
	if pid != os.Getpid() {
		return nil, errors.New("LISTEN_PID does not match current process")
	}

	count, err := strconv.Atoi(fdsRaw)
	if err != nil {
		return nil, fmt.Errorf("parse LISTEN_FDS: %w", err)
	}
	if count <= 0 {
		return nil, errors.New("LISTEN_FDS must be greater than zero")
	}

	listeners := make([]ActivatedListener, 0, count)
	for i := 0; i < count; i++ {
		fd := listenFdsStart + i
		file := os.NewFile(uintptr(fd), fmt.Sprintf("LISTEN_FD_%d", i))
		ln, err := net.FileListener(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("net.FileListener(%d): %w", fd, err)
		}
		listeners = append(listeners, ActivatedListener{Listener: ln, Name: file.Name()})
		_ = file.Close()
		syscall.CloseOnExec(fd)
	}

	return listeners, nil
}
