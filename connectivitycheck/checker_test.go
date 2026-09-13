package connectivitycheck

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func occupiedPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener, listener.Addr().(*net.TCPAddr).Port
}

func TestListenWithPortHandoffWaitsForPriorSidecar(t *testing.T) {
	prior, port := occupiedPort(t)
	defer prior.Close()
	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		prior.Close()
		close(released)
	}()
	listener, err := listenWithPortHandoff(port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	<-released
}

func TestListenWithPortHandoffFailsClosedAfterDeadline(t *testing.T) {
	prior, port := occupiedPort(t)
	defer prior.Close()
	listener, err := listenWithPortHandoff(port, 40*time.Millisecond)
	if listener != nil {
		listener.Close()
		t.Fatal("unexpected listener while prior sidecar owns the port")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("expected port-in-use error after deadline, got %v", err)
	}
}
