// Quic Pluggable Transport Server.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	quic "github.com/lucas-clemente/quic-go"
)

var serverInfo pt.ServerInfo
var handlerChan = make(chan int)

var certificatePath = flag.String("certificate", "", "Path to TLS certificate.")
var keyPath = flag.String("key", "", "Path to TLS private key.")

func copyLoop(stream quic.Stream, or net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(or, stream)
		wg.Done()
	}()

	go func() {
		io.Copy(stream, or)
		wg.Done()
	}()

	wg.Wait()
}

func handleSession(session quic.Session) {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	defer session.Close(nil)

	stream, err := session.AcceptStream()

	if err != nil {
		return
	}

	or, err := pt.DialOr(&serverInfo, session.RemoteAddr().String(), "quic")

	if err != nil {
		return
	}

	defer or.Close()

	copyLoop(stream, or)
}

func acceptLoop(listener quic.Listener) {
	defer listener.Close()

	for {
		session, err := listener.Accept()

		if err != nil {
			netErr, ok := err.(net.Error)

			if ok && netErr.Temporary() {
				continue
			}

			return
		}

		go handleSession(session)
	}
}

func main() {
	flag.Parse()

	serverInfo, err := pt.ServerSetup(nil)

	if err != nil {
		os.Exit(1)
	}

	certificate, err := tls.LoadX509KeyPair(*certificatePath, *keyPath)

	if err != nil {
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	listeners := make([]quic.Listener, 0)

	for _, bindAddr := range serverInfo.Bindaddrs {
		if bindAddr.MethodName == "quic" {
			listener, err := quic.ListenAddr(bindAddr.Addr.String(), tlsConfig, nil)

			if err != nil {
				pt.SmethodError(bindAddr.MethodName, err.Error())
				break
			}

			go acceptLoop(listener)

			pt.Smethod(bindAddr.MethodName, listener.Addr())
			listeners = append(listeners, listener)
		} else {
			pt.SmethodError(bindAddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

	numHandlers := 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}

	for _, listener := range listeners {
		listener.Close()
	}

	for n := range handlerChan {
		numHandlers += n
		if numHandlers == 0 {
			break
		}
	}
}
