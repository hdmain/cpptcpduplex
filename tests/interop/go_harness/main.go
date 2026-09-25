package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hdmain/tcpduplex"
)

func main() {
	binDir := "."
	if len(os.Args) > 1 {
		binDir = os.Args[1]
	}
	cppServer := resolve(binDir, "cpp_echo_server")
	cppClient := resolve(binDir, "cpp_echo_client")

	fmt.Println("=== Go client → C++ server ===")
	if err := goClientToCppServer(cppServer); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Println("=== C++ client → Go server ===")
	if err := cppClientToGoServer(cppClient); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Println("=== Go↔Go PSK (crypto parity baseline) ===")
	if err := pskGoRoundTrip(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Println("All interop tests passed")
}

func resolve(dir, name string) string {
	for _, candidate := range []string{
		filepath.Join(dir, name+".exe"),
		filepath.Join(dir, name),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join(dir, name)
}

func goClientToCppServer(cppServer string) error {
	cmd := exec.Command(cppServer, "127.0.0.1:0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	sc := bufio.NewScanner(stdout)
	if !sc.Scan() {
		return fmt.Errorf("no READY line from cpp server")
	}
	line := sc.Text()
	if !strings.HasPrefix(line, "READY ") {
		return fmt.Errorf("unexpected: %q", line)
	}
	addr := strings.TrimPrefix(line, "READY ")

	cli, err := tcpduplex.Dial(addr)
	if err != nil {
		return err
	}
	defer cli.Close()

	msg := []byte("interop-go-to-cpp")
	if err := cli.Send(msg); err != nil {
		return err
	}
	got, err := cli.Receive()
	if err != nil {
		return err
	}
	if string(got) != string(msg) {
		return fmt.Errorf("echo mismatch: %q", got)
	}
	return nil
}

func cppClientToGoServer(cppClient string) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		srv, err := tcpduplex.ServeConn(raw)
		if err != nil {
			errCh <- err
			return
		}
		defer srv.Close()
		msg, err := srv.Receive()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- srv.Send(msg)
	}()

	out, err := exec.Command(cppClient, ln.Addr().String(), "interop-cpp-to-go").CombinedOutput()
	if err != nil {
		return fmt.Errorf("cpp client: %v (%s)", err, out)
	}
	if strings.TrimSpace(string(out)) != "interop-cpp-to-go" {
		return fmt.Errorf("unexpected cpp client output: %q", out)
	}
	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("go server timed out")
	}
}

func pskGoRoundTrip() error {
	cfg := tcpduplex.DefaultConfig()
	cfg.Handshake.PreSharedKey = []byte("interop-psk")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		srv, err := tcpduplex.ServeConnContext(context.Background(), raw, cfg)
		if err != nil {
			errCh <- err
			return
		}
		defer srv.Close()
		msg, err := srv.Receive()
		if err != nil {
			errCh <- err
			return
		}
		if string(msg) != "psk-ping" {
			errCh <- fmt.Errorf("bad msg %q", msg)
			return
		}
		errCh <- srv.Send([]byte("psk-pong"))
	}()

	cli, err := tcpduplex.DialContext(context.Background(), ln.Addr().String(), cfg)
	if err != nil {
		return err
	}
	defer cli.Close()
	if err := cli.Send([]byte("psk-ping")); err != nil {
		return err
	}
	got, err := cli.Receive()
	if err != nil {
		return err
	}
	if string(got) != "psk-pong" {
		return fmt.Errorf("psk mismatch %q", got)
	}
	return <-errCh
}
