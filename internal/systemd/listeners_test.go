package systemd

import "testing"

func TestListenersRequiresEnv(t *testing.T) {
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	if _, err := Listeners(); err == nil {
		t.Fatal("expected error when env is missing")
	}
}
