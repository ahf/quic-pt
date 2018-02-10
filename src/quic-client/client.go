// Copyright (c) 2018 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Quic Pluggable Transport Client.
package main

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	quic "github.com/lucas-clemente/quic-go"
)

var handlerChan = make(chan int)

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

func handleClient(connection *pt.SocksConn) {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	defer connection.Close()

	session, err := quic.DialAddr(connection.Req.Target, &tls.Config{InsecureSkipVerify: true}, nil)

	if err != nil {
		connection.Reject()
		return
	}

	defer session.Close(nil)

	stream, err := session.OpenStreamSync()

	if err != nil {
		connection.Reject()
		return
	}

	err = connection.Grant(session.RemoteAddr().(*net.TCPAddr))

	copyLoop(stream, connection)
}

func acceptLoop(listener *pt.SocksListener) {
	defer listener.Close()

	for {
		connection, err := listener.AcceptSocks()

		if err != nil {
			netErr, ok := err.(net.Error)

			if ok && netErr.Temporary() {
				continue
			}

			return
		}

		go handleClient(connection)
	}
}

func main() {
	clientInfo, err := pt.ClientSetup(nil)

	if err != nil {
		os.Exit(1)
	}

	if clientInfo.ProxyURL != nil {
		pt.ProxyError("proxy unsupported")
		os.Exit(1)
	}

	listeners := make([]net.Listener, 0)

	for _, methodName := range clientInfo.MethodNames {
		if methodName == "quic" {
			listener, err := pt.ListenSocks("tcp", "127.0.0.1:0")

			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}

			go acceptLoop(listener)

			pt.Cmethod(methodName, listener.Version(), listener.Addr())
			listeners = append(listeners, listener)
		} else {
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

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
