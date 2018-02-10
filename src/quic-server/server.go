// Copyright (c) 2018 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Quic Pluggable Transport Server.
package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	quic "github.com/lucas-clemente/quic-go"
)

var handlerChan = make(chan int)

var certificatePath = flag.String("certificate", "", "Path to TLS certificate.")
var keyPath = flag.String("key", "", "Path to TLS private key.")
var logFile = flag.String("log-file", "", "Path to log file.")

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

func handleSession(session quic.Session, serverInfo *pt.ServerInfo) {
	log.Printf("Opened Quic session with %s", session.RemoteAddr())
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
		session.Close(nil)
		log.Printf("Ended Quic session with %s", session.RemoteAddr())
	}()

	stream, err := session.AcceptStream()

	if err != nil {
		log.Printf("Unable to create Quic stream: %s", err)
		return
	}

	log.Printf("Succesfully created Quic stream with %s", session.RemoteAddr())

	log.Printf("Connecting to Onion Router")
	or, err := pt.DialOr(serverInfo, session.RemoteAddr().String(), "quic")

	if err != nil {
		log.Printf("Unable to connect to Onion Router: %s", err)
		return
	}

	defer or.Close()

	copyLoop(stream, or)
}

func acceptLoop(listener quic.Listener, serverInfo *pt.ServerInfo) {
	defer listener.Close()

	for {
		session, err := listener.Accept()

		if err != nil {
			log.Printf("Error accepting session: %s", err)
			return
		}

		go handleSession(session, serverInfo)
	}
}

func main() {
	flag.Parse()

	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)

		if err != nil {
			log.Fatalf("Unable to open log file: %s", err)
		}

		log.SetOutput(file)
		defer file.Close()
	}

	serverInfo, err := pt.ServerSetup(nil)

	if err != nil {
		log.Fatalf("Unable to setup PT server: %s", err)
	}

	log.Printf("Loading TLS certificate from: %s", *certificatePath)
	log.Printf("Loading TLS private key from: %s", *keyPath)
	certificate, err := tls.LoadX509KeyPair(*certificatePath, *keyPath)

	if err != nil {
		log.Fatalf("Unable to load TLS certificates: %s", err)
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

			log.Printf("Started Quic listener: %s", bindAddr.Addr.String())
			go acceptLoop(listener, &serverInfo)

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
