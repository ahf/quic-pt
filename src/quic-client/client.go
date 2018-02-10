// Copyright (c) 2018 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Quic Pluggable Transport Client.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	quic "github.com/lucas-clemente/quic-go"
)

var handlerChan = make(chan int)

var logFile = flag.String("log-file", "", "Path to log file.")
var certificatePin = flag.String("certificate-pin", "", "SHA2-256 pin of the server certificate, encoded in hex.")
var publicKeyPin = flag.String("public-key-pin", "", "SHA2-256 pin of the server public key, encoded in hex.")

func matched(b bool) string {
	if b {
		return "matched pinned value"
	} else {
		return "didn't match pinned value"
	}
}

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
		connection.Close()
		log.Printf("Ending connection to %s", connection.Req.Target)
	}()

	tlsConfig := &tls.Config{
		// Note that we allow an insecure connection to be established, such
		// that we can inspect the certificate from the server and terminate
		// the connection if it doesn't match our pin.
		InsecureSkipVerify: true,
	}

	log.Printf("Connecting to %s", connection.Req.Target)
	session, err := quic.DialAddr(connection.Req.Target, tlsConfig, nil)

	if err != nil {
		log.Printf("Unable to connect to Quic server: %s", err)
		connection.Reject()
		return
	}

	log.Printf("Connected to %s", connection.Req.Target)
	defer session.Close(nil)

	// Do SHA2-256 key pin check here.
	pinValid := true
	state := session.ConnectionState()

	for _, peerCertificate := range state.PeerCertificates {
		// Do public key pinning:
		publicKeyHash := sha256.New()
		publicKeyHash.Write(peerCertificate.RawSubjectPublicKeyInfo)
		publicKeyHashHex := hex.EncodeToString(publicKeyHash.Sum(nil))

		// Do certificate pinning:
		certificateHash := sha256.New()
		certificateHash.Write(peerCertificate.Raw)
		certificateHashHex := hex.EncodeToString(certificateHash.Sum(nil))

		// Do pin check.
		publicKeyPinValid := true

		if *publicKeyPin != "" {
			if strings.ToLower(*publicKeyPin) != strings.ToLower(publicKeyHashHex) {
				publicKeyPinValid = false
			}
			log.Printf("  Public key:  '%s' %s (SHA2-256)", publicKeyHashHex, matched(publicKeyPinValid))
		}

		certificatePinValid := true

		if *certificatePin != "" {
			if strings.ToLower(*certificatePin) != strings.ToLower(certificateHashHex) {
				certificatePinValid = false
			}

			log.Printf("  Certificate: '%s' %s (SHA2-256)", certificateHashHex, matched(certificatePinValid))
		}

		pinValid = publicKeyPinValid && certificatePinValid

		if !pinValid {
			log.Printf("TLS certificate and/or public key did not match pinned values.")
			return
		}
	}

	stream, err := session.OpenStreamSync()

	if err != nil {
		log.Printf("Unable to create Quic stream: %s", err)
		connection.Reject()
		return
	}

	// FIXME(ahf): Figure out why Grant() takes an net.TCPAddr, but ignores it?
	err = connection.Grant(nil)

	if err != nil {
		log.Printf("Unable to grant session with %s", session.RemoteAddr())
		return
	}

	log.Printf("Granting session with %s", session.RemoteAddr())
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
	flag.Parse()

	if *logFile != "" {
		file, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)

		if err != nil {
			log.Fatalf("Unable to open log file: %s", err)
		}

		log.SetOutput(file)
		defer file.Close()
	}

	if *publicKeyPin == "" && *certificatePin == "" {
		log.Fatalf("Certificate and/or public key pin missing.")
	}

	clientInfo, err := pt.ClientSetup(nil)

	if err != nil {
		log.Fatalf("Unable to setup PT Client")
	}

	if clientInfo.ProxyURL != nil {
		log.Fatalf("Proxy unsupported")
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
