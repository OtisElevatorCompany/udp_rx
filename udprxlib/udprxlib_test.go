// Copyright 2018 Otis Elevator Company. All rights reserved.
// Use of this source code is govered by the MIT license which
// can be found in the LICENSE file.

// Author: Jeremy Mill: jeremy.mill@otis.com

// Otis udp_rx software has been designed to utilize information
// security technology described in the Category 5 – Part 2 of the
// Commerce Control List, within Part 774 of the Export Administration
// Regulations (“EAR”)(15 CFR 774).  However, the Otis udp_rx software
// has been made publicly available in accordance with Part 742.15(b)
// of the EAR and is therefore not subject to U.S. export regulations.
// Before downloading this software, be aware that the country in which
// you are located may have restrictions related to the import, download,
// possession, use and/or reexport of encryption items.  It is your
// responsibility to comply with any applicable laws and regulations
// pertaining the import, download, possession, use and/or reexport of
// encryption items.
package udprxlib

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// var cakeypath, certpath, keypath string
var cacertpath = "../keys/ca.crt"
var keypath = "../keys/server.key"
var certpath = "../keys/server.crt"

func modifyKeyPathsWindows() {
	if isWindows() {
		cacertpath = strings.Replace(cacertpath, "/", "\\", -1)
		// cakeypath = strings.Replace(cakeypath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
		certpath = strings.Replace(certpath, "/", "\\", -1)
	}
}

// TestCheckMutexMap checks the checkMutexMapMutex method
func TestCheckMutexMap(t *testing.T) {
	created := checkMutexMapMutex("192.168.1.100")
	if !created {
		t.Errorf("Did not create a mutex")
	}
	created = checkMutexMapMutex("192.168.1.100")
	if created {
		t.Errorf("Created a new mutex when we shouldn't have")
	}
}

// TestGetConn checks the getConn method
func TestGetConn(t *testing.T) {
	// setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	// create a tls socket on localhost:
	ln := setupTLS(rootCAs)
	go handleIncomingTLS(ln)
	// end setup, start test

	clientConf := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	header := UDPRxHeader{
		MajorVersion: 1,
		MinorVersion: 0,
		PatchVersion: 0,
		PortNumber:   50300,
		DestIPAddr:   net.IPv4(127, 0, 0, 1),
	}
	conn, err := getConn(header, clientConf, ":55554")
	if err != nil {
		t.Error("getConn returned an error")
	}
	conn.Write([]byte("Hello\n"))
}
func setupTLS(rootCAs *x509.CertPool) net.Listener {
	log.Warning("prepping incoming tls")
	fmt.Println("prepping to handle incoming TLS...")
	modifyKeyPathsWindows()
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	ln, err := tls.Listen("tcp", ":55554", serverConf)
	if err != nil {
		log.Panic("error listening to tls - " + err.Error())
	}
	return ln
}
func handleIncomingTLS(ln net.Listener) {
	for {
		fmt.Println("ready to accept connections...")
		conn, _ := ln.Accept()
		defer conn.Close()
		r := bufio.NewReader(conn)
		// buf := make([]byte, 1024)
		r.ReadLine()
		// io.ReadAtLeast(r, buf, 2)
		break
	}
}

// TestConnAddRemove checks the addConn and removeConn methods
func TestConnAddRemove(t *testing.T) {
	addConn("192.168.1.100", "192.168.1.102", nil)
	addConn("192.168.1.100", "192.168.1.102", nil)
	addConn("192.168.1.101", "192.168.1.102", nil)
	header := UDPRxHeader{
		MajorVersion: 1,
		MinorVersion: 0,
		PatchVersion: 0,
		PortNumber:   50300,
		DestIPAddr:   net.IPv4(192, 168, 1, 100),
		SourceIPAddr: net.IPv4(192, 168, 1, 102),
	}
	removeConn(header)
	removeConn(UDPRxHeader{})
}

// TestHandleConn tests the handleConn method
func TestHandleConn(t *testing.T) {
	// create a server to handle incoming connections
	ln := buildListener()
	go tcpServer(ln)
	conn, _ := net.Dial("tcp", "127.0.0.1:8081")
	handleConnection(conn, testSendUDP)
}
func testSendUDP(srcipstr string, destipstr string, srcprt uint, destprt uint, data []byte, counter int) error {
	_, _, err := ParseIps(srcipstr, destipstr)
	if destprt != 4498 {
		fmt.Println("Destport wrong: ", destprt)
		panic("destport isn't correct")
	}
	if srcprt != 4499 {
		panic("srcprt isn't correct")
	}
	for i := 0; i < 11; i++ {
		if data[i] != (byte)(10-i) {
			panic("data malformed")
		}
	}
	return err
}
func buildListener() net.Listener {
	ln, _ := net.Listen("tcp", ":8081")
	return ln
}
func tcpServer(ln net.Listener) {
	conn, _ := ln.Accept()
	barray := make([]byte, 1024)
	// len
	barray[0] = 0
	barray[1] = 13
	// sourceport
	barray[2] = 0x11
	barray[3] = 0x93
	// destport
	barray[4] = 0x11
	barray[5] = 0x92
	for i := 0; i < 11; i++ {
		barray[6+i] = (byte)(10 - i)
	}
	conn.Write(barray)
	conn.Close()
}

// TestForwardPacket tests the forwardPacket method
func TestForwardPacket(t *testing.T) {
	// setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	// setup client config
	clientConf := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	readyTLS := make(chan bool)
	go listenTLS(readyTLS)
	// block until readyTLS
	tlsReady := <-readyTLS
	log.Infof("tlsReady: %t", tlsReady)
	buf := make([]byte, 11)
	for i := 0; i < 11; i++ {
		buf[i] = (byte)(10 - i)
	}
	// make a header
	header := UDPRxHeader{
		MajorVersion: 1,
		MinorVersion: 0,
		PatchVersion: 0,
		PortNumber:   50300,
		DestIPAddr:   net.IPv4(127, 0, 0, 1),
	}
	// send it
	err = forwardPacket(clientConf, header, buf, 55554, ":55553")
	if err != nil {
		t.Error("Error forwarding packets")
	}
}
func listenTLS(readyTLS chan bool) {
	// setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	lan, _ := tls.Listen("tcp", ":55553", serverConf)
	readyTLS <- true
	for {
		conn, _ := lan.Accept()
		defer conn.Close()
		r := bufio.NewReader(conn)
		// check length bytes
		lenbuf := make([]byte, 2)
		io.ReadAtLeast(r, lenbuf, 2)
		if lenbuf[0] != 0 || lenbuf[1] != 11 {
			panic("length wrong")
		}
		// check srcport bytes
		srcprtbuf := make([]byte, 2)
		io.ReadAtLeast(r, srcprtbuf, 2)
		if srcprtbuf[0] != 0xD9 || srcprtbuf[1] != 0x02 {
			panic("srcprt bytes wrong")
		}
		// check destport
		destprtbuf := make([]byte, 2)
		io.ReadAtLeast(r, destprtbuf, 2)
		if destprtbuf[0] != 0xC4 || destprtbuf[1] != 0x7C {
			panic("destprt bytes wrong")
		}
		// finally, check data
		databuf := make([]byte, 11)
		io.ReadAtLeast(r, databuf, 11)
		for i := 0; i < 11; i++ {
			if databuf[i] != (byte)(10-i) {
				panic("data byte wrong")
			}
		}
		break
	}
}

func TestTCPListener(t *testing.T) {
	// setup test
	modifyKeyPathsWindows()
	listenAddrSting := ""
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	doneChan := make(chan error)
	// override handleConnection
	handleConnectionFunc = mockHandleConnection
	// start the listener and send a message
	go TCPListener(&listenAddrSting, serverConf, doneChan)
	time.Sleep(time.Second * 3)
	sendTLSMessage(t, cer, rootCAs)
	// close the connection
	TCPSocketListener.Close()
	// get the done channel
	err = <-doneChan
	if err == nil {
		t.Error("Should have gotten an error")
	}
}
func sendTLSMessage(t *testing.T, cer tls.Certificate, rootCAs *x509.CertPool) {
	clientConf := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:55554", clientConf)
	if err != nil {
		t.Fatalf("getConn returned an error. Error: %s", err.Error())
	}
	// write a message to
	conn.Write([]byte{1, 2, 3})
}
func mockHandleConnection(conn net.Conn, sender sendUDPFn) {
	// conn.Close()
	b := make([]byte, 1024)
	conn.Read(b)
	return
}

var testUDPListenerT *testing.T

func TestUDPListener(t *testing.T) {
	modifyKeyPathsWindows()
	testUDPListenerT = t
	listenAddr := ""
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	clientConf := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	doneChan := make(chan error)
	// start the UDP listener
	forwardPacketFunc = mockForwardPacket
	go UDPListener(&listenAddr, clientConf, doneChan)
	time.Sleep(time.Second * 3)
	// send a packet to the UDP listener
	ServerAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:55555")
	LocalAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("error building testing udp sender")
	}
	conn, err := net.DialUDP("udp", LocalAddr, ServerAddr)
	if err != nil {
		t.Fatal("error connecting to udp listener")
	}
	b := []byte{192, 168, 1, 50, 11, 92, 5, 4}
	_, err = conn.Write(b)
	if err != nil {
		t.Fatal("error writing to udp listener")
	}
	UDPSocketListener.Close()
	// get the done channel
	err = <-doneChan
	if err == nil {
		t.Error("Should have gotten an error")
	}
}
func mockForwardPacket(conf *tls.Config, header UDPRxHeader, data []byte, srcprt int, remoteTLSPort string) error {
	if header.DestIPAddr.String() != "192.168.1.50" {
		testUDPListenerT.Fatal("Bad ip input to forward packet")
	}
	if data[0] != 11 {
		testUDPListenerT.Fatal("Bad port byte 0")
	}
	if data[1] != 92 {
		testUDPListenerT.Fatal("Bad port byte 1")
	}
	if data[2] != 5 {
		testUDPListenerT.Fatal("Bad data byte 0")
	}
	if data[3] != 4 {
		testUDPListenerT.Fatal("Bad data byte 1")
	}
	return nil
}

func TestParseHeader4NoSrc(t *testing.T) {
	buf := make([]byte, 1024)
	// start
	buf[0] = 0x75
	// header version
	buf[1] = 0x01
	buf[2] = 0x02
	buf[3] = 0x03
	// port = 50300 in 2 bytes, big endian
	buf[4] = 0xC4
	buf[5] = 0x7C
	// ipv4
	buf[6] = 0x04
	// to 192.168.1.100
	buf[7] = 192
	buf[8] = 168
	buf[9] = 1
	buf[10] = 100
	// end
	buf[11] = 0x80
	header, err := parseHeader(&buf)
	if err != nil {
		t.Error(err)
	}
	if header.MajorVersion != 1 {
		t.Error("wrong major version")
	}
	if header.MinorVersion != 2 {
		t.Error("wrong minor version")
	}
	if header.PatchVersion != 3 {
		t.Error("wrong patch version")
	}
	if header.PortNumber != 50300 {
		t.Error("Wrong Port Number")
	}
	if header.DestIPAddr.String() != "192.168.1.100" {
		t.Errorf("Wrong Dest IP. Got %s", header.DestIPAddr.String())
	}
}

func TestParseHeader6NoSrc(t *testing.T) {
	buf := make([]byte, 1024)
	// start
	buf[0] = 0x75
	// header version
	buf[1] = 0x01
	buf[2] = 0x02
	buf[3] = 0x03
	// port = 50300 in 2 bytes, big endian
	buf[4] = 0xC4
	buf[5] = 0x7C
	// ipv6
	buf[6] = 0x06
	// to 2600:8805:cc00:cc:ed0e:1b36:d342:474e
	destip := net.ParseIP("2600:8805:cc00:cc:ed0e:1b36:d342:474e")
	for i := 0; i < 16; i++ {
		buf[7+i] = destip[i]
	}
	// end
	buf[23] = 0x80
	header, err := parseHeader(&buf)
	if err != nil {
		t.Error(err)
	}
	if header.MajorVersion != 1 {
		t.Error("wrong major version")
	}
	if header.MinorVersion != 2 {
		t.Error("wrong minor version")
	}
	if header.PatchVersion != 3 {
		t.Error("wrong patch version")
	}
	if header.PortNumber != 50300 {
		t.Error("Wrong Port Number")
	}
	if header.DestIPAddr.String() != "2600:8805:cc00:cc:ed0e:1b36:d342:474e" {
		t.Errorf("Wrong Dest IP. Got %s", header.DestIPAddr.String())
	}
}

// UDP message handling correctness

// TestParseHeader4WithSource verifies that an IPv4 header containing both
// destination and source addresses is parsed correctly and leaves the payload intact.
func TestParseHeader4WithSource(t *testing.T) {
	buf := make([]byte, 0, 32)
	buf = append(buf,
		0x75,
		0x01, 0x02, 0x03,
		0xC4, 0x7C,
		0x04,
		192, 168, 1, 100,
		0x76,
		192, 168, 1, 101,
		0x80,
		0xAA, 0xBB,
	)

	header, err := parseHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if header.MajorVersion != 1 || header.MinorVersion != 2 || header.PatchVersion != 3 {
		t.Fatalf("unexpected version %d.%d.%d", header.MajorVersion, header.MinorVersion, header.PatchVersion)
	}
	if header.PortNumber != 50300 {
		t.Fatalf("unexpected port number %d", header.PortNumber)
	}
	if header.DestIPAddr.String() != "192.168.1.100" {
		t.Fatalf("expected destination IP 192.168.1.100, got %s", header.DestIPAddr.String())
	}
	if header.SourceIPAddr.String() != "192.168.1.101" {
		t.Fatalf("expected source IP 192.168.1.101, got %s", header.SourceIPAddr.String())
	}
	if !bytes.Equal(buf, []byte{0xAA, 0xBB}) {
		t.Fatalf("expected payload bytes [170 187], got %v", buf)
	}
}

// TestParseHeader6WithSource verifies that an IPv6 header containing both
// destination and source addresses is parsed correctly and preserves the payload bytes.
func TestParseHeader6WithSource(t *testing.T) {
	destip := net.ParseIP("2600:8805:cc00:cc:ed0e:1b36:d342:474e")
	srcip := net.ParseIP("2600:8805:cc00:cc:ed0e:1b36:d342:474f")
	buf := make([]byte, 0, 64)
	buf = append(buf,
		0x75,
		0x01, 0x02, 0x03,
		0xC4, 0x7C,
		0x06,
	)
	buf = append(buf, destip...)
	buf = append(buf, 0x76)
	buf = append(buf, srcip...)
	buf = append(buf, 0x80, 0xAA, 0xBB, 0xCC)

	header, err := parseHeader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if header.DestIPAddr.String() != destip.String() {
		t.Fatalf("expected destination IP %s, got %s", destip.String(), header.DestIPAddr.String())
	}
	if header.SourceIPAddr.String() != srcip.String() {
		t.Fatalf("expected source IP %s, got %s", srcip.String(), header.SourceIPAddr.String())
	}
	if !bytes.Equal(buf, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("expected payload bytes [170 187 204], got %v", buf)
	}
}

// TestForwardPacketEncodesZeroLengthPayload verifies that forwarding an empty
// payload still produces the expected six-byte metadata frame over TLS.
func TestForwardPacketEncodesZeroLengthPayload(t *testing.T) {
	resetConnCacheState(t)
	oldNetProfiling := netProfiling
	t.Cleanup(func() {
		netProfiling = oldNetProfiling
	})
	netProfiling = false

	rootCAs, serverCert, clientCert := buildMutualTLSConfigs(t)
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	clientConf := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	frameRead := make(chan []byte, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 6)
		n, err := io.ReadFull(conn, buf)
		if err != nil {
			acceptErr <- err
			return
		}
		frameRead <- append([]byte(nil), buf[:n]...)
	}()

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1"), PortNumber: 50300}
	port := listener.Addr().(*net.TCPAddr).Port
	err = forwardPacket(clientConf, header, nil, 55554, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("forwardPacket returned an unexpected error for zero payload: %v", err)
	}

	select {
	case err := <-acceptErr:
		t.Fatalf("listener failed while reading zero-length forwarded frame: %v", err)
	case frame := <-frameRead:
		if len(frame) != 6 {
			t.Fatalf("expected 6-byte frame for zero payload, got %d", len(frame))
		}
		declaredLength := (int(frame[0]) << 8) + int(frame[1])
		if declaredLength != 0 {
			t.Fatalf("expected declared payload length 0, got %d", declaredLength)
		}
		if frame[2] != 0xD9 || frame[3] != 0x02 {
			t.Fatalf("expected source port bytes [217 2], got [%d %d]", frame[2], frame[3])
		}
		if frame[4] != 0xC4 || frame[5] != 0x7C {
			t.Fatalf("expected destination port bytes [196 124], got [%d %d]", frame[4], frame[5])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forwardPacket to emit zero-length frame")
	}
}

// TestForwardPacketShortPayloadUsesExactLength verifies that small TLS-forwarded UDP payloads 
// keep the exact declared message length and do not add extra bytes.
func TestForwardPacketShortPayloadUsesExactLength(t *testing.T) {
	resetConnCacheState(t)
	oldNetProfiling := netProfiling
	t.Cleanup(func() {
		netProfiling = oldNetProfiling
	})
	netProfiling = false

	rootCAs, serverCert, clientCert := buildMutualTLSConfigs(t)
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	clientConf := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	frameRead := make(chan []byte, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, err := io.ReadFull(conn, buf[:8])
		if err != nil {
			acceptErr <- err
			return
		}
		frameRead <- append([]byte(nil), buf[:n]...)
	}()

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1"), PortNumber: 50300}
	port := listener.Addr().(*net.TCPAddr).Port
	payload := []byte{0xAA, 0xBB}
	err = forwardPacket(clientConf, header, payload, 55554, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("forwardPacket returned an unexpected error: %v", err)
	}

	select {
	case err := <-acceptErr:
		t.Fatalf("listener failed while reading forwarded frame: %v", err)
	case frame := <-frameRead:
		if len(frame) != 8 {
			t.Fatalf("expected exact forwarded frame length 8, got %d", len(frame))
		}
		declaredLength := (int(frame[0]) << 8) + int(frame[1])
		if declaredLength != len(payload) {
			t.Fatalf("expected declared payload length %d, got %d", len(payload), declaredLength)
		}
		if frame[2] != 0xD9 || frame[3] != 0x02 {
			t.Fatalf("expected source port bytes [217 2], got [%d %d]", frame[2], frame[3])
		}
		if frame[4] != 0xC4 || frame[5] != 0x7C {
			t.Fatalf("expected destination port bytes [196 124], got [%d %d]", frame[4], frame[5])
		}
		if !bytes.Equal(frame[6:], payload) {
			t.Fatalf("expected exact forwarded payload %v, got %v", payload, frame[6:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forwardPacket to emit the short payload frame")
	}
}

// TestUDPListenerForwardPacketTrimsHeaderWithSourceIP verifies that remote forwarding strips 
// both destination and source IP header bytes before calling forwardPacket.
func TestUDPListenerForwardPacketTrimsHeaderWithSourceIP(t *testing.T) {
	listenAddr := ""
	doneChan := make(chan error, 1)
	forwarded := make(chan udpListenerForwardCapture, 1)
	oldForwardPacketFunc := forwardPacketFunc
	forwardPacketFunc = func(conf *tls.Config, header UDPRxHeader, data []byte, srcprt int, remoteTLSPort string) error {
		payloadCopy := append([]byte(nil), data...)
		forwarded <- udpListenerForwardCapture{header: header, data: payloadCopy, srcprt: srcprt, remoteTLSPort: remoteTLSPort}
		return nil
	}
	t.Cleanup(func() {
		forwardPacketFunc = oldForwardPacketFunc
		if UDPSocketListener != nil {
			UDPSocketListener.Close()
		}
		select {
		case <-doneChan:
		default:
		}
	})

	go UDPListener(&listenAddr, &tls.Config{}, doneChan)
	time.Sleep(300 * time.Millisecond)

	sender, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 55555})
	if err != nil {
		t.Fatalf("failed to connect to UDP listener: %v", err)
	}
	defer sender.Close()

	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	packet := append([]byte{0x75, 0x01, 0x00, 0x00, 0xD9, 0x3A, 0x04, 192, 168, 1, 50, 0x76, 192, 168, 1, 99, 0x80}, payload...)
	if _, err := sender.Write(packet); err != nil {
		t.Fatalf("failed to write UDP packet: %v", err)
	}

	select {
	case result := <-forwarded:
		if result.header.DestIPAddr.String() != "192.168.1.50" {
			t.Fatalf("expected destination IP 192.168.1.50, got %s", result.header.DestIPAddr.String())
		}
		if result.header.SourceIPAddr.String() != "192.168.1.99" {
			t.Fatalf("expected source IP 192.168.1.99, got %s", result.header.SourceIPAddr.String())
		}
		if !bytes.Equal(result.data, payload) {
			t.Fatalf("expected forwarded payload %v, got %v", payload, result.data)
		}
		if bytes.Contains(result.data, []byte{0x75, 0x01, 0x00, 0x00}) {
			t.Fatal("forwarded payload still contains udp_rx header bytes")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for UDPListener to forward the trimmed payload")
	}
}

// Concurrency tests for sync.Map-based connection caching and retry

// TestConnMapConcurrentReadsSameKey verifies that many goroutines can repeatedly load 
// the same cached key safely.
func TestConnMapConcurrentReadsSameKey(t *testing.T) {
	resetConnCacheState(t)

	const goroutineCount = 48
	const iterations = 200
	key := "192.168.10.1|192.168.10.2"
	wantConn := &tls.Conn{}
	connMap.Store(key, wantConn)

	errCh := make(chan error, goroutineCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				gotConn, ok := connMap.Load(key)
				if !ok {
					errCh <- fmt.Errorf("expected cached key %s to exist", key)
					return
				}
				if gotConn != wantConn {
					errCh <- fmt.Errorf("expected cached connection %p, got %p", wantConn, gotConn)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestConnMapConcurrentReadsDifferentKeys verifies that many goroutines can repeatedly load 
// different cached keys safely.
func TestConnMapConcurrentReadsDifferentKeys(t *testing.T) {
	resetConnCacheState(t)

	const keyCount = 32
	const iterations = 200
	expected := make(map[string]*tls.Conn, keyCount)
	for i := 0; i < keyCount; i++ {
		key := fmt.Sprintf("192.168.11.%d|192.168.12.%d", i+1, i+1)
		conn := &tls.Conn{}
		expected[key] = conn
		connMap.Store(key, conn)
	}

	errCh := make(chan error, keyCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for key, wantConn := range expected {
		wg.Add(1)
		go func(key string, wantConn *tls.Conn) {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				gotConn, ok := connMap.Load(key)
				if !ok {
					errCh <- fmt.Errorf("expected cached key %s to exist", key)
					return
				}
				if gotConn != wantConn {
					errCh <- fmt.Errorf("expected cached connection %p for key %s, got %p", wantConn, key, gotConn)
					return
				}
			}
		}(key, wantConn)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestAddConnConcurrentDifferentAddressPairs verifies that concurrent writers can populate
// many independent destination/source pairs safely once the per-key mutexes exist.
func TestAddConnConcurrentDifferentAddressPairs(t *testing.T) {
	resetConnCacheState(t)

	const pairCount = 40
	type pair struct {
		key         string
		fallbackKey string
		conn        *tls.Conn
	}
	pairs := make([]pair, 0, pairCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < pairCount; i++ {
		dest := fmt.Sprintf("192.168.20.%d", i+1)
		src := fmt.Sprintf("192.168.21.%d", i+1)
		conn := &tls.Conn{}
		pairs = append(pairs, pair{
			key:         fmt.Sprintf("%s|%s", dest, src),
			fallbackKey: fmt.Sprintf("%s|", dest),
			conn:        conn,
		})

		checkMutexMapMutex(fmt.Sprintf("%s|%s", dest, src))
		checkMutexMapMutex(fmt.Sprintf("%s|", dest))

		wg.Add(1)
		go func(dest string, src string, conn *tls.Conn) {
			defer wg.Done()
			<-start
			addConn(dest, src, conn)
		}(dest, src, conn)
	}

	close(start)
	wg.Wait()

	for _, pair := range pairs {
		storedConn, ok := connMap.Load(pair.key)
		if !ok || storedConn != pair.conn {
			t.Fatalf("expected full key %s to point at %p, got %p", pair.key, pair.conn, storedConn)
		}
		fallbackConn, ok := connMap.Load(pair.fallbackKey)
		if !ok || fallbackConn != pair.conn {
			t.Fatalf("expected fallback key %s to point at %p, got %p", pair.fallbackKey, pair.conn, fallbackConn)
		}
	}
	if len(mutexMap) != pairCount*2 {
		t.Fatalf("expected %d mutex entries after different-key writes, got %d", pairCount*2, len(mutexMap))
	}
}

// TestConnMapHighVolumeConcurrentWrites verifies that the connection cache tolerates a large
// number of concurrent writes across unique keys.
func TestConnMapHighVolumeConcurrentWrites(t *testing.T) {
	resetConnCacheState(t)

	const workerCount = 24
	const writesPerWorker = 80
	var wg sync.WaitGroup
	start := make(chan struct{})

	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for writeIndex := 0; writeIndex < writesPerWorker; writeIndex++ {
				key := fmt.Sprintf("worker-%d|write-%d", worker, writeIndex)
				connMap.Store(key, &tls.Conn{})
			}
		}(worker)
	}

	close(start)
	wg.Wait()

	count := 0
	connMap.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	wantCount := workerCount * writesPerWorker
	if count != wantCount {
		t.Fatalf("expected %d cached entries after high-volume concurrent writes, got %d", wantCount, count)
	}
}

// TestConnMapReadsWhileWritesOngoing verifies that repeated loads remain safe while other
// goroutines keep updating the same key.
func TestConnMapReadsWhileWritesOngoing(t *testing.T) {
	resetConnCacheState(t)

	const writerCount = 8
	const readerCount = 16
	const iterations = 300
	key := "192.168.30.1|"
	knownValues := []*tls.Conn{&tls.Conn{}, &tls.Conn{}, &tls.Conn{}, &tls.Conn{}}
	valueSet := map[*tls.Conn]bool{}
	for _, conn := range knownValues {
		valueSet[conn] = true
	}
	connMap.Store(key, knownValues[0])

	errCh := make(chan error, readerCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for writer := 0; writer < writerCount; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				connMap.Store(key, knownValues[(writer+iteration)%len(knownValues)])
			}
		}(writer)
	}

	for reader := 0; reader < readerCount; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				gotConn, ok := connMap.Load(key)
				if !ok {
					errCh <- fmt.Errorf("expected key %s to remain visible during reads", key)
					return
				}
				tlsConn, ok := gotConn.(*tls.Conn)
				if !ok || !valueSet[tlsConn] {
					errCh <- fmt.Errorf("unexpected connection value %v while reads and writes overlap", gotConn)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestConnMapDeleteWhileReadHappens verifies that readers can keep loading a key safely
// while another goroutine deletes and restores it.
func TestConnMapDeleteWhileReadHappens(t *testing.T) {
	resetConnCacheState(t)

	const readerCount = 12
	const iterations = 250
	key := "192.168.31.1|"
	wantConn := &tls.Conn{}
	connMap.Store(key, wantConn)

	errCh := make(chan error, readerCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			connMap.Delete(key)
			connMap.Store(key, wantConn)
		}
	}()

	for reader := 0; reader < readerCount; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				gotConn, ok := connMap.Load(key)
				if ok && gotConn != wantConn {
					errCh <- fmt.Errorf("expected deleted/restored key to contain %p, got %p", wantConn, gotConn)
					return
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestConnMapUpdateWhileDeleteHappens verifies that updates and deletes can race on the same
// key without corrupting the cache state.
func TestConnMapUpdateWhileDeleteHappens(t *testing.T) {
	resetConnCacheState(t)

	const updaterCount = 8
	const iterations = 250
	key := "192.168.32.1|"
	knownValues := []*tls.Conn{&tls.Conn{}, &tls.Conn{}, &tls.Conn{}}
	valueSet := map[*tls.Conn]bool{}
	for _, conn := range knownValues {
		valueSet[conn] = true
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for iteration := 0; iteration < iterations; iteration++ {
			connMap.Delete(key)
		}
	}()

	for updater := 0; updater < updaterCount; updater++ {
		wg.Add(1)
		go func(updater int) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				connMap.Store(key, knownValues[(updater+iteration)%len(knownValues)])
			}
		}(updater)
	}

	close(start)
	wg.Wait()

	gotConn, ok := connMap.Load(key)
	if ok {
		tlsConn, ok := gotConn.(*tls.Conn)
		if !ok || !valueSet[tlsConn] {
			t.Fatalf("expected final updated connection to be one of the known values, got %v", gotConn)
		}
	}
}

// TestAddConnAndRemoveConnConcurrentSameDestinationNoDeadlock verifies that concurrent updates
// and deletes for one destination complete without deadlocking once the touched
// per-key mutexes already exist.
func TestAddConnAndRemoveConnConcurrentSameDestinationNoDeadlock(t *testing.T) {
	resetConnCacheState(t)

	const writerCount = 6
	const removerCount = 4
	const iterations = 120
	for writer := 0; writer < writerCount; writer++ {
		src := fmt.Sprintf("192.168.40.%d", (writer%8)+1)
		checkMutexMapMutex(fmt.Sprintf("%s|%s", "192.168.41.1", src))
	}
	checkMutexMapMutex("192.168.41.1|")

	var wg sync.WaitGroup
	start := make(chan struct{})
	done := make(chan struct{})

	for writer := 0; writer < writerCount; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				src := fmt.Sprintf("192.168.40.%d", (writer%8)+1)
				addConn("192.168.41.1", src, &tls.Conn{})
			}
		}(writer)
	}

	for remover := 0; remover < removerCount; remover++ {
		wg.Add(1)
		go func(remover int) {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				removeConn(UDPRxHeader{DestIPAddr: net.IPv4(192, 168, 41, 1), SourceIPAddr: net.IPv4(192, 168, 40, byte((remover%8)+1))})
			}
		}(remover)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	close(start)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent addConn/removeConn operations did not complete; possible deadlock")
	}
}

// TestGetConnTimeoutEarlyReturnReleasesPerKeyLock verifies that the getConn timeout path
// releases its per-key mutex before returning.
func TestGetConnTimeoutEarlyReturnReleasesPerKeyLock(t *testing.T) {
	resetConnCacheState(t)
	ConnTimeoutVal = 60

	header := UDPRxHeader{DestIPAddr: net.IPv4(192, 168, 50, 1)}
	mapKey := "192.168.50.1|"
	lastConnFail.Store(mapKey, time.Now())

	conn, err := getConn(header, nil, ":1")
	if conn != nil {
		t.Fatal("expected no connection on timeout early return")
	}
	if _, ok := err.(*connTimeoutError); !ok {
		t.Fatalf("expected connTimeoutError from getConn early return, got %T", err)
	}

	done := make(chan struct{})
	go func() {
		mutexMap[mapKey].Lock()
		mutexMap[mapKey].Unlock()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("per-key mutex remained locked after getConn early return")
	}
}

// TestMutexWriterMutexRecoversAfterPanic verifies that the writer mutex remains usable after
// a panic guarded by a deferred unlock.
func TestMutexWriterMutexRecoversAfterPanic(t *testing.T) {
	recovered := false
	func() {
		defer func() {
			if recover() != nil {
				recovered = true
			}
		}()
		mutexWriterMutex.Lock()
		defer mutexWriterMutex.Unlock()
		panic("simulated panic inside critical section")
	}()

	if !recovered {
		t.Fatal("expected panic inside critical section to be recovered")
	}

	done := make(chan struct{})
	go func() {
		mutexWriterMutex.Lock()
		mutexWriterMutex.Unlock()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writer mutex remained locked after panic recovery")
	}
}

// TestCheckMutexMapMutexConcurrentCreation verifies that the post-2019 mutex map protection
// creates exactly one mutex for a hot key even under concurrent access.
func TestCheckMutexMapMutexConcurrentCreation(t *testing.T) {
	resetConnCacheState(t)

	const goroutineCount = 32
	var createdCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start //wait
			if checkMutexMapMutex("192.168.1.100|192.168.1.101") {
				atomic.AddInt32(&createdCount, 1)
			}
		}()
	}

	close(start) // release all goroutines at once to maximize contention on the mutex map
	wg.Wait()

	if createdCount != 1 {
		t.Fatalf("expected exactly one goroutine to create the mutex, got %d", createdCount)
	}
	if len(mutexMap) != 1 {
		t.Fatalf("expected exactly one cached mutex for the hot key, got %d", len(mutexMap))
	}
	if mutexMap["192.168.1.100|192.168.1.101"] == nil {
		t.Fatal("expected mutex map to contain the hot key after concurrent creation")
	}
}

// TestAddConnConcurrentSameAddressPair verifies that concurrent cache population for one
// destination/source pair leaves one stable full key and one stable fallback key entry.
func TestAddConnConcurrentSameAddressPair(t *testing.T) {
	resetConnCacheState(t)

	const goroutineCount = 24
	sharedConn := &tls.Conn{}
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			addConn("192.168.1.210", "192.168.1.211", sharedConn)
		}()
	}

	close(start)
	wg.Wait()

	fullKeyConn, ok := connMap.Load("192.168.1.210|192.168.1.211")
	if !ok {
		t.Fatal("expected concurrent addConn calls to cache the full key")
	}
	if fullKeyConn != sharedConn {
		t.Fatal("expected concurrent addConn calls to preserve the shared full-key connection")
	}
	fallbackConn, ok := connMap.Load("192.168.1.210|")
	if !ok {
		t.Fatal("expected concurrent addConn calls to cache the fallback key")
	}
	if fallbackConn != sharedConn {
		t.Fatal("expected concurrent addConn calls to preserve the shared fallback connection")
	}
	if len(mutexMap) != 2 {
		t.Fatalf("expected full-key and fallback-key mutexes to exist, got %d mutex entries", len(mutexMap))
	}
}

// TestRemoveConnConcurrentSameDestination verifies that concurrent removal of one destination
// key space is safe and does not remove unrelated cached destinations.
func TestRemoveConnConcurrentSameDestination(t *testing.T) {
	resetConnCacheState(t)

	matchingConn := &tls.Conn{}
	unrelatedConn := &tls.Conn{}
	connMap.Store("192.168.1.100|192.168.1.101", matchingConn)
	connMap.Store("192.168.1.100|", matchingConn)
	connMap.Store("192.168.1.102|192.168.1.103", unrelatedConn)

	header := UDPRxHeader{
		DestIPAddr:   net.IPv4(192, 168, 1, 100),
		SourceIPAddr: net.IPv4(192, 168, 1, 101),
	}

	const goroutineCount = 16
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			removeConn(header)
		}()
	}

	close(start)
	wg.Wait()

	if _, ok := connMap.Load("192.168.1.100|192.168.1.101"); ok {
		t.Fatal("expected concurrent removeConn calls to delete the full key")
	}
	if _, ok := connMap.Load("192.168.1.100|"); ok {
		t.Fatal("expected concurrent removeConn calls to delete the fallback key")
	}
	remainingConn, ok := connMap.Load("192.168.1.102|192.168.1.103")
	if !ok {
		t.Fatal("expected unrelated destination cache entry to remain after concurrent removeConn calls")
	}
	if remainingConn != unrelatedConn {
		t.Fatal("expected unrelated cached connection to remain unchanged after concurrent removeConn calls")
	}
}

type udpListenerForwardCapture struct {
	header        UDPRxHeader
	data          []byte
	srcprt        int
	remoteTLSPort string
}

// TestCheckMutexMapConcurrentSingleAddress verifies that concurrent callers racing on
// one address create only one per-address mutex entry.
func TestCheckMutexMapConcurrentSingleAddress(t *testing.T) {
	resetConnCacheState(t)

	const goroutineCount = 32
	var createdCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	key := "192.168.1.230|192.168.1.231"

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if checkMutexMapMutex(key) {
				atomic.AddInt32(&createdCount, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if createdCount != 1 {
		t.Fatalf("expected exactly one mutex creator for %s, got %d", key, createdCount)
	}
	if len(mutexMap) != 1 {
		t.Fatalf("expected one mutex entry after concurrent creation, got %d", len(mutexMap))
	}
	if mutexMap[key] == nil {
		t.Fatalf("expected mutex entry for key %s", key)
	}
}

// TestAddConnConcurrentSameAddressKeepsFirstConnection verifies that concurrent addConn calls
// for one address pair preserve the first connection in both cache keys.
func TestAddConnConcurrentSameAddressKeepsFirstConnection(t *testing.T) {
	resetConnCacheState(t)

	const goroutineCount = 24
	firstConn := &tls.Conn{}
	secondConn := &tls.Conn{}
	var wg sync.WaitGroup
	start := make(chan struct{})

	addConn("192.168.1.240", "192.168.1.241", firstConn)

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			addConn("192.168.1.240", "192.168.1.241", secondConn)
		}()
	}

	close(start)
	wg.Wait()

	fullKeyConn, ok := connMap.Load("192.168.1.240|192.168.1.241")
	if !ok {
		t.Fatal("expected full key to remain cached after concurrent addConn calls")
	}
	if fullKeyConn != firstConn {
		t.Fatal("expected first cached connection to remain the winner for the full key")
	}
	fallbackConn, ok := connMap.Load("192.168.1.240|")
	if !ok {
		t.Fatal("expected fallback key to remain cached after concurrent addConn calls")
	}
	if fallbackConn != firstConn {
		t.Fatal("expected first cached connection to remain the winner for the fallback key")
	}
}

// TestGetConnConcurrentCachedLookups verifies that concurrent cached lookups all return the
// same stored connection without falling through to dialing.
func TestGetConnConcurrentCachedLookups(t *testing.T) {
	resetConnCacheState(t)

	header := UDPRxHeader{
		DestIPAddr:   net.IPv4(192, 168, 1, 250),
		SourceIPAddr: net.IPv4(192, 168, 1, 251),
	}
	cachedConn := &tls.Conn{}
	connMap.Store("192.168.1.250|192.168.1.251", cachedConn)
	lastConnFail.Store("192.168.1.250|192.168.1.251", time.Now())

	const goroutineCount = 32
	errCh := make(chan error, goroutineCount)
	connCh := make(chan *tls.Conn, goroutineCount)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := getConn(header, nil, ":1")
			errCh <- err
			connCh <- conn
		}()
	}

	close(start)
	wg.Wait()
	close(errCh)
	close(connCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("expected cached concurrent getConn lookups to avoid dial errors, got %v", err)
		}
	}
	for conn := range connCh {
		if conn != cachedConn {
			t.Fatal("expected all concurrent getConn lookups to return the cached connection")
		}
	}
	if len(mutexMap) != 1 {
		t.Fatalf("expected one mutex entry for the cached lookup key, got %d", len(mutexMap))
	}
}

// TestGetConnReturnsConnTimeoutAfterRecentFailure verifies the sync.Map-backed retry suppression path after a recent dial failure.
func TestGetConnReturnsConnTimeoutAfterRecentFailure(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}
	lastConnFail.Store("127.0.0.1|", time.Now())

	_, err := getConn(header, &tls.Config{}, ":1")
	if err == nil {
		t.Fatal("expected getConn to reject a recent failed connection attempt")
	}
	if _, ok := err.(*connTimeoutError); !ok {
		t.Fatalf("expected connTimeoutError, got %T", err)
	}
}

// TestGetConnReturnsCachedConnection verifies that getConn returns an already cached TLS connection without redialing.
func TestGetConnReturnsCachedConnection(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	wantConn := &tls.Conn{}
	connMap.Store("127.0.0.1|", wantConn)

	gotConn, err := getConn(UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}, &tls.Config{}, ":1")
	if err != nil {
		t.Fatalf("expected cached connection lookup to succeed: %v", err)
	}
	if gotConn != wantConn {
		t.Fatal("expected getConn to return the cached tls connection")
	}
}

// TestAddConnStoresFallbackKey verifies that addConn stores both the full dest|src key and the destination-only fallback key.
func TestAddConnStoresFallbackKey(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	conn := &tls.Conn{}
	addConn("192.168.1.10", "192.168.1.20", conn)

	storedConn, ok := connMap.Load("192.168.1.10|192.168.1.20")
	if !ok || storedConn != conn {
		t.Fatal("expected addConn to cache the complete destination and source key")
	}
	fallbackConn, ok := connMap.Load("192.168.1.10|")
	if !ok || fallbackConn != conn {
		t.Fatal("expected addConn to cache the destination-only fallback key")
	}
}

// TestAddConnDoesNotOverwriteExistingConnection verifies that addConn preserves an already cached connection for the same sync.Map keys.
func TestAddConnDoesNotOverwriteExistingConnection(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	existingConn := &tls.Conn{}
	replacementConn := &tls.Conn{}
	connMap.Store("192.168.1.10|192.168.1.20", existingConn)
	connMap.Store("192.168.1.10|", existingConn)

	addConn("192.168.1.10", "192.168.1.20", replacementConn)

	storedConn, ok := connMap.Load("192.168.1.10|192.168.1.20")
	if !ok || storedConn != existingConn {
		t.Fatal("expected addConn to preserve the existing full-key connection")
	}
	fallbackConn, ok := connMap.Load("192.168.1.10|")
	if !ok || fallbackConn != existingConn {
		t.Fatal("expected addConn to preserve the existing destination-only connection")
	}
	if storedConn == replacementConn || fallbackConn == replacementConn {
		t.Fatal("expected replacement connection to be ignored when cache entries already exist")
	}
}

// TestRemoveConnDeletesOnlyMatchingDestination verifies that removeConn clears cached entries only for the requested destination host.
func TestRemoveConnDeletesOnlyMatchingDestination(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	matchingConn := &tls.Conn{}
	otherConn := &tls.Conn{}
	connMap.Store("10.0.0.1|10.0.0.2", matchingConn)
	connMap.Store("10.0.0.1|", matchingConn)
	connMap.Store("10.0.0.3|10.0.0.4", otherConn)

	removeConn(UDPRxHeader{DestIPAddr: net.ParseIP("10.0.0.1"), SourceIPAddr: net.ParseIP("10.0.0.2")})

	if _, ok := connMap.Load("10.0.0.1|10.0.0.2"); ok {
		t.Fatal("expected matching full key to be removed")
	}
	if _, ok := connMap.Load("10.0.0.1|"); ok {
		t.Fatal("expected matching destination-only key to be removed")
	}
	if _, ok := connMap.Load("10.0.0.3|10.0.0.4"); !ok {
		t.Fatal("expected non-matching destination key to remain cached")
	}
}

// TestGetConnStoresLastFailureTime verifies that a failed dial through the sync.Map path records the failure timestamp for retry suppression.
func TestGetConnStoresLastFailureTime(t *testing.T) {
	connMap = sync.Map{}
	lastConnFail = sync.Map{}
	mutexMap = make(map[string]*sync.Mutex)

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}
	_, err := getConn(header, &tls.Config{}, ":1")
	if err == nil {
		t.Fatal("expected getConn dial attempt to fail for an unopened local port")
	}
	if _, ok := err.(*connTimeoutError); ok {
		t.Fatal("expected the first failed dial to return the dial error, not a connTimeoutError")
	}
	lastFail, ok := lastConnFail.Load("127.0.0.1|")
	if !ok {
		t.Fatal("expected getConn to store a failure timestamp after a dial error")
	}
	if _, ok := lastFail.(time.Time); !ok {
		t.Fatalf("expected stored failure value to be a time.Time, got %T", lastFail)
	}
	if _, ok := connMap.Load("127.0.0.1|"); ok {
		t.Fatal("expected failed dial attempts not to cache a TLS connection")
	}
}

// TestGetClientValidatorAcceptsMatchingRemoteIP verifies that peer validation succeeds when the remote IP matches a certificate SAN.
func TestGetClientValidatorAcceptsMatchingRemoteIP(t *testing.T) {
	rootPool, cert := buildClientValidationChain(t, []net.IP{net.ParseIP("127.0.0.1")})
	rootCAs = rootPool
	validator := getClientValidator(&tls.ClientHelloInfo{Conn: stubNetConn{remoteAddr: stubAddr("127.0.0.1:4444")}})

	if err := validator(nil, [][]*x509.Certificate{{cert}}); err != nil {
		t.Fatalf("expected validator to accept matching remote IP: %v", err)
	}
}

// TestGetClientValidatorRejectsMismatchedRemoteIP verifies that peer validation rejects a client when the remote IP is not in the certificate SANs.
func TestGetClientValidatorRejectsMismatchedRemoteIP(t *testing.T) {
	rootPool, cert := buildClientValidationChain(t, []net.IP{net.ParseIP("127.0.0.1")})
	rootCAs = rootPool
	validator := getClientValidator(&tls.ClientHelloInfo{Conn: stubNetConn{remoteAddr: stubAddr("127.0.0.2:4444")}})

	if err := validator(nil, [][]*x509.Certificate{{cert}}); err == nil {
		t.Fatal("expected validator to reject a mismatched remote IP")
	}
}

// Client identity / certificate hostname validation

// TestGetClientValidatorAcceptsMatchingRemoteHostname verifies that peer validation succeeds
// when the remote hostname matches a DNS SAN in the client certificate.
func TestGetClientValidatorAcceptsMatchingRemoteHostname(t *testing.T) {
	rootPool, cert := buildClientValidationChainWithHostnames(t, []string{"client.example.com"})
	rootCAs = rootPool
	validator := getClientValidator(&tls.ClientHelloInfo{Conn: stubNetConn{remoteAddr: stubAddr("client.example.com:4444")}})

	if err := validator(nil, [][]*x509.Certificate{{cert}}); err != nil {
		t.Fatalf("expected validator to accept matching remote hostname: %v", err)
	}
}

// TestGetClientValidatorRejectsMismatchedRemoteHostname verifies that peer validation rejects
// a client when the remote hostname does not match the DNS SANs.
func TestGetClientValidatorRejectsMismatchedRemoteHostname(t *testing.T) {
	rootPool, cert := buildClientValidationChainWithHostnames(t, []string{"client.example.com"})
	rootCAs = rootPool
	validator := getClientValidator(&tls.ClientHelloInfo{Conn: stubNetConn{remoteAddr: stubAddr("other.example.com:4444")}})

	if err := validator(nil, [][]*x509.Certificate{{cert}}); err == nil {
		t.Fatal("expected validator to reject a mismatched remote hostname")
	}
}

// TestUDPListenerLocalhostTrimsHeader verifies the localhost forwarding fix that strips the udp_rx header before calling SendUDP.
func TestUDPListenerLocalhostTrimsHeader(t *testing.T) {
	listenAddr := ""
	doneChan := make(chan error, 1)
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 55610})
	if err != nil {
		t.Fatalf("failed to create localhost receiver: %v", err)
	}
	defer receiver.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set receiver deadline: %v", err)
	}

	go UDPListener(&listenAddr, &tls.Config{}, doneChan)
	t.Cleanup(func() {
		if UDPSocketListener != nil {
			UDPSocketListener.Close()
		}
		select {
		case <-doneChan:
		default:
		}
	})
	time.Sleep(300 * time.Millisecond)

	sender, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 55555})
	if err != nil {
		t.Fatalf("failed to connect to UDP listener: %v", err)
	}
	defer sender.Close()

	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	packet := append([]byte{0x75, 0x01, 0x00, 0x00, 0xD9, 0x3A, 0x04, 127, 0, 0, 1, 0x80}, payload...)
	if _, err := sender.Write(packet); err != nil {
		t.Fatalf("failed to write localhost packet: %v", err)
	}

	buf := make([]byte, 64)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to receive localhost-forwarded packet: %v", err)
	}
	if n != len(payload)+6 {
		t.Fatalf("expected localhost payload length %d, got %d", len(payload)+6, n)
	}
	if !bytes.Equal(buf[6:n], payload) {
		t.Fatalf("expected forwarded payload %v, got %v", payload, buf[6:n])
	}
	if bytes.Contains(buf[6:n], []byte{0x75, 0x01, 0x00, 0x00}) {
		t.Fatal("forwarded localhost payload still contains udprx header bytes")
	}
}

type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

type stubNetConn struct {
	remoteAddr net.Addr
}

func (c stubNetConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c stubNetConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c stubNetConn) Close() error                       { return nil }
func (c stubNetConn) LocalAddr() net.Addr                { return stubAddr("127.0.0.1:0") }
func (c stubNetConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c stubNetConn) SetDeadline(_ time.Time) error      { return nil }
func (c stubNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c stubNetConn) SetWriteDeadline(_ time.Time) error { return nil }

// buildClientValidationChain creates a disposable CA and client certificate chain for peer validation tests.
func buildClientValidationChain(t *testing.T, ips []net.IP) (*x509.CertPool, *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "udp-rx-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "udp-rx-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("failed to marshal leaf key: %v", err)
	}
	_, err = tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	)
	if err != nil {
		t.Fatalf("failed to build tls certificate: %v", err)
	}

	return rootPool, leafCert
}

// buildClientValidationChainWithHostnames creates a disposable CA and client certificate chain
// with DNS SANs for hostname validation tests.
func buildClientValidationChainWithHostnames(t *testing.T, hostnames []string) (*x509.CertPool, *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "udp-rx-test-root-hostname"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "udp-rx-client-hostname"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     hostnames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return rootPool, leafCert
}

// buildMutualTLSConfigs creates a disposable CA plus server and client certificates for tests that need a full mTLS handshake.
func buildMutualTLSConfigs(t *testing.T) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "udp-rx-mtls-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	serverCert := buildSignedTLSCertificate(t, caCert, caKey, big.NewInt(11), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert := buildSignedTLSCertificate(t, caCert, caKey, big.NewInt(12), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)

	return rootPool, serverCert, clientCert
}

// buildSignedTLSCertificate creates a signed tls.Certificate for either server or client auth in tests.
func buildSignedTLSCertificate(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int, usages []x509.ExtKeyUsage, ips []net.IP) tls.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "udp-rx-mtls-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  usages,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("failed to marshal leaf key: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	)
	if err != nil {
		t.Fatalf("failed to build tls certificate: %v", err)
	}

	return tlsCert
}

// Test helper for the new connection-cache tests.
// Its purpose is to make each test start with clean shared state, because those tests depend on package-level globals
// resetConnCacheState clears the shared cache globals used by the sync.Map tests.
func resetConnCacheState(t *testing.T) {
	t.Helper()

	clearSyncMap := func(syncMap *sync.Map) {
		syncMap.Range(func(key, value interface{}) bool {
			syncMap.Delete(key)
			return true
		})
	}

	oldConnTimeoutVal := ConnTimeoutVal

	clearSyncMap(&connMap)
	clearSyncMap(&lastConnFail)
	mutexMap = make(map[string]*sync.Mutex)
	ConnTimeoutVal = 10

	t.Cleanup(func() {
		clearSyncMap(&connMap)
		clearSyncMap(&lastConnFail)
		mutexMap = make(map[string]*sync.Mutex)
		ConnTimeoutVal = oldConnTimeoutVal
	})
}

// verifies the cache behavior of addConn from both the full key and fallback key
// perspectives, ensuring that existing connections are not overwritten
// when the same destination and source are added multiple times
// with a different connection object.
func TestAddConnStoresBothKeysWithoutOverwrite(t *testing.T) {
	resetConnCacheState(t)

	firstConn := &tls.Conn{}
	secondConn := &tls.Conn{}

	// addConn writes both the full dest|src key and the dest-only fallback key.
	addConn("192.168.1.100", "192.168.1.102", firstConn)
	addConn("192.168.1.100", "192.168.1.102", secondConn)

	fullKeyConn, ok := connMap.Load("192.168.1.100|192.168.1.102")
	if !ok {
		t.Fatal("expected full destination and source key to be cached")
	}
	if fullKeyConn.(*tls.Conn) != firstConn {
		t.Fatal("expected addConn to preserve the first cached connection for the full key")
	}

	noSrcKeyConn, ok := connMap.Load("192.168.1.100|")
	if !ok {
		t.Fatal("expected destination-only key to be cached")
	}
	if noSrcKeyConn.(*tls.Conn) != firstConn {
		t.Fatal("expected addConn to preserve the first cached connection for the destination-only key")
	}
}

// Verifies that removeConn removes only the cached connection entries for
// one destination IP and does not disturb entries for other destinations.
func TestRemoveConnDeletesOnlyMatchingDestinationEntries(t *testing.T) {
	resetConnCacheState(t)

	matchingConn := &tls.Conn{}
	unrelatedConn := &tls.Conn{}

	// Seed the cache with two entries for one destination and one unrelated destination.
	connMap.Store("192.168.1.100|192.168.1.102", matchingConn)
	connMap.Store("192.168.1.100|", matchingConn)
	connMap.Store("192.168.1.101|192.168.1.102", unrelatedConn)

	header := UDPRxHeader{
		DestIPAddr:   net.IPv4(192, 168, 1, 100),
		SourceIPAddr: net.IPv4(192, 168, 1, 102),
	}
	// anything starting with 192.168.1.100 should be deleted,
	// and anything starting with another destination should remain.
	removeConn(header)

	if _, ok := connMap.Load("192.168.1.100|192.168.1.102"); ok {
		t.Fatal("expected removeConn to delete the full key for the destination")
	}
	if _, ok := connMap.Load("192.168.1.100|"); ok {
		t.Fatal("expected removeConn to delete the destination-only key")
	}
	remainingConn, ok := connMap.Load("192.168.1.101|192.168.1.102")
	if !ok {
		t.Fatal("expected removeConn to keep unrelated destination entries")
	}
	if remainingConn.(*tls.Conn) != unrelatedConn {
		t.Fatal("expected unrelated cached connection to remain unchanged")
	}
}

// verifies that getConn reuses an already cached connection instead of
// trying to create a new TLS connection.
func TestGetConnReturnsCachedConnectionWithoutDial(t *testing.T) {
	resetConnCacheState(t)

	header := UDPRxHeader{
		DestIPAddr:   net.IPv4(192, 168, 1, 100),
		SourceIPAddr: net.IPv4(192, 168, 1, 102),
	}
	cachedConn := &tls.Conn{}
	// A cached connection should win even if a recent failure timestamp also exists.
	connMap.Store("192.168.1.100|192.168.1.102", cachedConn)
	lastConnFail.Store("192.168.1.100|192.168.1.102", time.Now())

	conn, err := getConn(header, nil, ":1")
	if err != nil {
		t.Fatalf("expected cached connection without error, got %v", err)
	}
	if conn != cachedConn {
		t.Fatal("expected getConn to return the cached connection for the full key")
	}
}

// Verifies the retry-throttling behavior in getConn.
// It checks that when there is no cached connection and the last connection
// failure happened recently, getConn must not try to create a new TLS connection
// yet. Instead, it should immediately return a connTimeoutError.
func TestGetConnReturnsTimeoutErrorAfterRecentFailure(t *testing.T) {
	resetConnCacheState(t)
	ConnTimeoutVal = 60

	header := UDPRxHeader{
		DestIPAddr: net.IPv4(192, 168, 1, 100),
	}
	// With no cached connection, a recent failure should short-circuit a redial attempt.
	lastConnFail.Store("192.168.1.100|", time.Now())

	conn, err := getConn(header, nil, ":1")
	if conn != nil {
		t.Fatal("expected no connection when the last failure is still within the timeout window")
	}
	if err == nil {
		t.Fatal("expected a timeout error when the last failure is recent")
	}
	if _, ok := err.(*connTimeoutError); !ok {
		t.Fatalf("expected connTimeoutError, got %T", err)
	}
}

// Security / TLS protocol upgrades tests

// TestGetServerConfigAllowsTLS12Through13 verifies the post-2019 TLS upgrade that allows
// TLS 1.2 and TLS 1.3 while still requiring verified client certificates.
func TestGetServerConfigAllowsTLS12Through13(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	pool := x509.NewCertPool()
	wantServerCert := &tls.Certificate{}
	config := GetServerConfig(pool, wantServerCert)
	if config.GetConfigForClient == nil {
		t.Fatal("expected GetServerConfig to provide a per-client TLS config callback")
	}

	nestedConfig, err := config.GetConfigForClient(&tls.ClientHelloInfo{Conn: stubNetConn{remoteAddr: stubAddr("127.0.0.1:4444")}})
	if err != nil {
		t.Fatalf("GetConfigForClient returned an unexpected error: %v", err)
	}
	if nestedConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected minimum TLS version %d, got %d", tls.VersionTLS12, nestedConfig.MinVersion)
	}
	if nestedConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("expected maximum TLS version %d, got %d", tls.VersionTLS13, nestedConfig.MaxVersion)
	}
	if nestedConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected RequireAndVerifyClientCert, got %v", nestedConfig.ClientAuth)
	}
	if nestedConfig.ClientCAs != pool {
		t.Fatal("expected returned TLS config to reuse the supplied root CA pool")
	}
	if nestedConfig.VerifyPeerCertificate == nil {
		t.Fatal("expected returned TLS config to install peer certificate validation")
	}
	if nestedConfig.GetCertificate == nil {
		t.Fatal("expected returned TLS config to expose a server certificate callback")
	}

	gotCert, err := nestedConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate returned an unexpected error: %v", err)
	}
	if gotCert != wantServerCert {
		t.Fatal("expected GetCertificate to return the server certificate supplied to GetServerConfig")
	}
}

// buildServerConfigTLSConfigs creates a disposable CA plus server and client certificates for
// GetServerConfig handshake tests.
func buildServerConfigTLSConfigs(t *testing.T, clientIPs []net.IP) (*x509.CertPool, tls.Certificate, tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "udp-rx-server-config-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	serverTLSCert := buildSignedTLSCertificate(t, caCert, caKey, big.NewInt(21), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	clientTLSCert := buildSignedTLSCertificate(t, caCert, caKey, big.NewInt(22), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, clientIPs)

	return rootPool, serverTLSCert, clientTLSCert
}

// TestGetConnWithSourceIPCreatesCachedConnection verifies the tls.DialWithDialer branch can
// establish and cache a source-bound TLS connection.
func TestGetConnWithSourceIPCreatesCachedConnection(t *testing.T) {
	resetConnCacheState(t)

	rootPool, serverTLSCert, clientTLSCert := buildMutualTLSConfigs(t)
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootPool,
	}
	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		acceptErr <- conn.(*tls.Conn).Handshake()
	}()

	header := UDPRxHeader{
		DestIPAddr:   net.ParseIP("127.0.0.1"),
		SourceIPAddr: net.ParseIP("127.0.0.1"),
	}
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := getConn(header, clientConf, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("expected getConn with source IP to succeed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected getConn with source IP to return a TLS connection")
	}

	storedConn, ok := connMap.Load("127.0.0.1|127.0.0.1")
	if !ok {
		t.Fatal("expected getConn to cache the source-bound TLS connection")
	}
	if storedConn != conn {
		t.Fatal("expected cached TLS connection to match the returned source-bound connection")
	}

	select {
	case err := <-acceptErr:
		if err != nil {
			t.Fatalf("server handshake failed for source-bound TLS connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for source-bound TLS handshake to complete")
	}
	conn.Close()
}

// TestGetConnWithSourceIPStoresLastFailureTime verifies that a failed tls.DialWithDialer
// stores the retry-suppression timestamp under the full dest|src key.
func TestGetConnWithSourceIPStoresLastFailureTime(t *testing.T) {
	resetConnCacheState(t)

	header := UDPRxHeader{
		DestIPAddr:   net.ParseIP("127.0.0.1"),
		SourceIPAddr: net.ParseIP("127.0.0.1"),
	}
	_, err := getConn(header, &tls.Config{}, ":1")
	if err == nil {
		t.Fatal("expected source-bound getConn dial attempt to fail for an unopened local port")
	}
	lastFail, ok := lastConnFail.Load("127.0.0.1|127.0.0.1")
	if !ok {
		t.Fatal("expected source-bound getConn failure to store a timestamp under the full key")
	}
	if _, ok := lastFail.(time.Time); !ok {
		t.Fatalf("expected source-bound failure timestamp to be a time.Time, got %T", lastFail)
	}
	if _, ok := connMap.Load("127.0.0.1|127.0.0.1"); ok {
		t.Fatal("expected failed source-bound getConn attempts not to cache a TLS connection")
	}
}

// TestGetServerConfigHandshakeAcceptsMatchingClientIP verifies that the callback-based server
// config completes a real mTLS handshake for a client whose certificate SAN matches the remote IP.
func TestGetServerConfigHandshakeAcceptsMatchingClientIP(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err != nil {
		t.Fatalf("expected GetServerConfig handshake to succeed: %v", err)
	}
	conn.Close()

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side GetServerConfig handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side GetServerConfig handshake")
	}
}

// TestGetServerConfigHandshakeRejectsUntrustedClientCert verifies that the callback-based
// server config rejects a client certificate signed by an unknown CA.
func TestGetServerConfigHandshakeRejectsUntrustedClientCert(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, _ := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	_, _, untrustedClientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{untrustedClientTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err == nil {
		conn.Close()
	}

	select {
	case err := <-serverHandshakeErr:
		if err == nil {
			t.Fatal("expected server-side handshake to fail for an untrusted client certificate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side GetServerConfig rejection")
	}
}

// TestGetServerConfigHandshakeRejectsTLS10Client verifies that the callback-based server
// config rejects a client restricted to TLS 1.0.
func TestGetServerConfigHandshakeRejectsTLS10Client(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err == nil {
		conn.Close()
	}

	select {
	case err := <-serverHandshakeErr:
		if err == nil {
			t.Fatal("expected server-side handshake to fail for a TLS 1.0-only client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.0 rejection")
	}
}

// TestGetServerConfigHandshakeRejectsTLS11Client verifies that the callback-based server
// config rejects a client restricted to TLS 1.1.
func TestGetServerConfigHandshakeRejectsTLS11Client(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS11,
		MaxVersion:   tls.VersionTLS11,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err == nil {
		conn.Close()
	}

	select {
	case err := <-serverHandshakeErr:
		if err == nil {
			t.Fatal("expected server-side handshake to fail for a TLS 1.1-only client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.1 rejection")
	}
}

// TestGetServerConfigHandshakeRejectsSSLv3Client verifies that the callback-based server
// config rejects an SSLv3-only client.
func TestGetServerConfigHandshakeRejectsSSLv3Client(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	const sslv3Version uint16 = 0x0300
	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   sslv3Version,
		MaxVersion:   sslv3Version,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err == nil {
		conn.Close()
	}

	select {
	case err := <-serverHandshakeErr:
		if err == nil {
			t.Fatal("expected server-side handshake to fail for an SSLv3-only client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side SSLv3 rejection")
	}
}

// TestGetServerConfigHandshakeAcceptsTLS12StrongCipher verifies that the callback-based
// server config accepts TLS 1.2 when the client is restricted to a strong ECDHE-ECDSA GCM cipher suite.
func TestGetServerConfigHandshakeAcceptsTLS12StrongCipher(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverStateCh := make(chan tls.ConnectionState, 1)
	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverHandshakeErr <- err
			return
		}
		serverStateCh <- tlsConn.ConnectionState()
		serverHandshakeErr <- nil
	}()

	const strongTLS12Cipher = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{strongTLS12Cipher},
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err != nil {
		t.Fatalf("expected TLS 1.2 strong-cipher handshake to succeed: %v", err)
	}
	clientState := conn.ConnectionState()
	conn.Close()

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side TLS 1.2 strong-cipher handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.2 strong-cipher handshake")
	}

	var serverState tls.ConnectionState
	select {
	case serverState = <-serverStateCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.2 connection state")
	}

	if clientState.Version != tls.VersionTLS12 {
		t.Fatalf("expected client TLS version %d, got %d", tls.VersionTLS12, clientState.Version)
	}
	if clientState.CipherSuite != strongTLS12Cipher {
		t.Fatalf("expected client cipher suite %d, got %d", strongTLS12Cipher, clientState.CipherSuite)
	}
	if serverState.Version != tls.VersionTLS12 {
		t.Fatalf("expected server TLS version %d, got %d", tls.VersionTLS12, serverState.Version)
	}
	if serverState.CipherSuite != strongTLS12Cipher {
		t.Fatalf("expected server cipher suite %d, got %d", strongTLS12Cipher, serverState.CipherSuite)
	}
}

// TestGetServerConfigHandshakeAcceptsTLS13DefaultCipherSuites verifies that the callback-based
// server config accepts TLS 1.3 using Go's default TLS 1.3 cipher suite set.
func TestGetServerConfigHandshakeAcceptsTLS13DefaultCipherSuites(t *testing.T) {
	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, clientTLSCert := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}
	defer listener.Close()

	serverStateCh := make(chan tls.ConnectionState, 1)
	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverHandshakeErr <- err
			return
		}
		serverStateCh <- tlsConn.ConnectionState()
		serverHandshakeErr <- nil
	}()

	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConf)
	if err != nil {
		t.Fatalf("expected TLS 1.3 default-cipher handshake to succeed: %v", err)
	}
	clientState := conn.ConnectionState()
	conn.Close()

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side TLS 1.3 default-cipher handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.3 default-cipher handshake")
	}

	var serverState tls.ConnectionState
	select {
	case serverState = <-serverStateCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.3 connection state")
	}

	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("expected client TLS version %d, got %d", tls.VersionTLS13, clientState.Version)
	}
	if serverState.Version != tls.VersionTLS13 {
		t.Fatalf("expected server TLS version %d, got %d", tls.VersionTLS13, serverState.Version)
	}
	if !isDefaultTLS13CipherSuite(clientState.CipherSuite) {
		t.Fatalf("expected client TLS 1.3 cipher suite to be a default TLS 1.3 suite, got %d", clientState.CipherSuite)
	}
	if !isDefaultTLS13CipherSuite(serverState.CipherSuite) {
		t.Fatalf("expected server TLS 1.3 cipher suite to be a default TLS 1.3 suite, got %d", serverState.CipherSuite)
	}
}

func isDefaultTLS13CipherSuite(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		return false
	}
}

// TestGetConnClientConnectsUsingTLS12 verifies that the client connection path can establish
// a TLS 1.2 session when the server is pinned to TLS 1.2.
func TestGetConnClientConnectsUsingTLS12(t *testing.T) {
	resetConnCacheState(t)

	listener, clientConf, serverStateCh, serverHandshakeErr := startClientConnectVersionTestServer(t, tls.VersionTLS12, tls.VersionTLS12)
	defer listener.Close()

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := getConn(header, clientConf, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("expected client getConn TLS 1.2 handshake to succeed: %v", err)
	}
	defer conn.Close()

	clientState := conn.ConnectionState()
	if clientState.Version != tls.VersionTLS12 {
		t.Fatalf("expected client TLS version %d, got %d", tls.VersionTLS12, clientState.Version)
	}

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side TLS 1.2 handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.2 handshake")
	}

	select {
	case serverState := <-serverStateCh:
		if serverState.Version != tls.VersionTLS12 {
			t.Fatalf("expected server TLS version %d, got %d", tls.VersionTLS12, serverState.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.2 connection state")
	}
}

// TestGetConnClientConnectsUsingTLS13 verifies that the client connection path can establish
// a TLS 1.3 session when the server is pinned to TLS 1.3.
func TestGetConnClientConnectsUsingTLS13(t *testing.T) {
	resetConnCacheState(t)

	listener, clientConf, serverStateCh, serverHandshakeErr := startClientConnectVersionTestServer(t, tls.VersionTLS13, tls.VersionTLS13)
	defer listener.Close()

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := getConn(header, clientConf, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("expected client getConn TLS 1.3 handshake to succeed: %v", err)
	}
	defer conn.Close()

	clientState := conn.ConnectionState()
	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("expected client TLS version %d, got %d", tls.VersionTLS13, clientState.Version)
	}

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side TLS 1.3 handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.3 handshake")
	}

	select {
	case serverState := <-serverStateCh:
		if serverState.Version != tls.VersionTLS13 {
			t.Fatalf("expected server TLS version %d, got %d", tls.VersionTLS13, serverState.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side TLS 1.3 connection state")
	}
}

// TestGetConnClientAutoNegotiatesTLSVersion verifies that the default client config
// auto-negotiates the highest mutually supported TLS version.
func TestGetConnClientAutoNegotiatesTLSVersion(t *testing.T) {
	resetConnCacheState(t)

	listener, clientConf, serverStateCh, serverHandshakeErr := startClientConnectVersionTestServer(t, tls.VersionTLS12, tls.VersionTLS13)
	defer listener.Close()

	header := UDPRxHeader{DestIPAddr: net.ParseIP("127.0.0.1")}
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := getConn(header, clientConf, fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("expected client auto-negotiated TLS handshake to succeed: %v", err)
	}
	defer conn.Close()

	clientState := conn.ConnectionState()
	if clientState.Version != tls.VersionTLS13 {
		t.Fatalf("expected auto-negotiated client TLS version %d, got %d", tls.VersionTLS13, clientState.Version)
	}

	select {
	case err := <-serverHandshakeErr:
		if err != nil {
			t.Fatalf("server-side auto-negotiated TLS handshake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side auto-negotiated TLS handshake")
	}

	select {
	case serverState := <-serverStateCh:
		if serverState.Version != tls.VersionTLS13 {
			t.Fatalf("expected auto-negotiated server TLS version %d, got %d", tls.VersionTLS13, serverState.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side auto-negotiated TLS connection state")
	}
}

func startClientConnectVersionTestServer(t *testing.T, minVersion uint16, maxVersion uint16) (net.Listener, *tls.Config, <-chan tls.ConnectionState, <-chan error) {
	t.Helper()

	rootPool, serverTLSCert, clientTLSCert := buildMutualTLSConfigs(t)
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootPool,
	}
	clientConf := &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientTLSCert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}

	serverStateCh := make(chan tls.ConnectionState, 1)
	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverHandshakeErr <- err
			return
		}
		serverStateCh <- tlsConn.ConnectionState()
		serverHandshakeErr <- nil
	}()

	return listener, clientConf, serverStateCh, serverHandshakeErr
}

// TestGetServerConfigHandshakeRejectsMalformedTLSVersion verifies that the callback-based
// server config rejects a syntactically malformed, unsupported TLS version during handshake setup.
func TestGetServerConfigHandshakeRejectsMalformedTLSVersion(t *testing.T) {
	listener, serverHandshakeErr := startRawClientHelloTestServer(t)
	defer listener.Close()

	rawClientHello := buildRawTLSClientHello(0x7f7f, 0x7f7f, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384})
	if err := sendRawClientHello(listener.Addr().String(), rawClientHello); err != nil {
		t.Fatalf("failed to send malformed TLS version ClientHello: %v", err)
	}

	assertServerHandshakeFailed(t, serverHandshakeErr, "malformed TLS version")
}

// TestGetServerConfigHandshakeRejectsTLS12RC4Cipher verifies that the callback-based server
// config rejects a TLS 1.2 client offering only the deprecated RC4 cipher.
func TestGetServerConfigHandshakeRejectsTLS12RC4Cipher(t *testing.T) {
	listener, serverHandshakeErr := startRawClientHelloTestServer(t)
	defer listener.Close()

	const tlsECDHEECDSAWithRC4128SHA uint16 = 0xC007
	rawClientHello := buildRawTLSClientHello(tls.VersionTLS12, tls.VersionTLS12, []uint16{tlsECDHEECDSAWithRC4128SHA})
	if err := sendRawClientHello(listener.Addr().String(), rawClientHello); err != nil {
		t.Fatalf("failed to send RC4-only TLS 1.2 ClientHello: %v", err)
	}

	assertServerHandshakeFailed(t, serverHandshakeErr, "TLS 1.2 RC4-only cipher")
}

// TestGetServerConfigHandshakeRejectsTLS123DESCipher verifies that the callback-based server
// config rejects a TLS 1.2 client offering only the deprecated 3DES cipher.
func TestGetServerConfigHandshakeRejectsTLS123DESCipher(t *testing.T) {
	listener, serverHandshakeErr := startRawClientHelloTestServer(t)
	defer listener.Close()

	const tlsECDHEECDSAWith3DESEDECBCSHA uint16 = 0xC008
	rawClientHello := buildRawTLSClientHello(tls.VersionTLS12, tls.VersionTLS12, []uint16{tlsECDHEECDSAWith3DESEDECBCSHA})
	if err := sendRawClientHello(listener.Addr().String(), rawClientHello); err != nil {
		t.Fatalf("failed to send 3DES-only TLS 1.2 ClientHello: %v", err)
	}

	assertServerHandshakeFailed(t, serverHandshakeErr, "TLS 1.2 3DES-only cipher")
}

// TestGetServerConfigHandshakeRejectsTLS12NullCipher verifies that the callback-based server
// config rejects a TLS 1.2 client offering only a NULL cipher suite.
func TestGetServerConfigHandshakeRejectsTLS12NullCipher(t *testing.T) {
	listener, serverHandshakeErr := startRawClientHelloTestServer(t)
	defer listener.Close()

	const tlsRSAWithNullSHA uint16 = 0x0002
	rawClientHello := buildRawTLSClientHello(tls.VersionTLS12, tls.VersionTLS12, []uint16{tlsRSAWithNullSHA})
	if err := sendRawClientHello(listener.Addr().String(), rawClientHello); err != nil {
		t.Fatalf("failed to send NULL-cipher TLS 1.2 ClientHello: %v", err)
	}

	assertServerHandshakeFailed(t, serverHandshakeErr, "TLS 1.2 NULL cipher")
}

// TestGetServerConfigHandshakeRejectsTLS12ExportCipher verifies that the callback-based
// server config rejects a TLS 1.2 client offering only an obsolete EXPORT cipher suite.
func TestGetServerConfigHandshakeRejectsTLS12ExportCipher(t *testing.T) {
	listener, serverHandshakeErr := startRawClientHelloTestServer(t)
	defer listener.Close()

	const tlsRSAExportWithRC440MD5 uint16 = 0x0003
	rawClientHello := buildRawTLSClientHello(tls.VersionTLS12, tls.VersionTLS12, []uint16{tlsRSAExportWithRC440MD5})
	if err := sendRawClientHello(listener.Addr().String(), rawClientHello); err != nil {
		t.Fatalf("failed to send EXPORT-cipher TLS 1.2 ClientHello: %v", err)
	}

	assertServerHandshakeFailed(t, serverHandshakeErr, "TLS 1.2 EXPORT cipher")
}

func startRawClientHelloTestServer(t *testing.T) (net.Listener, <-chan error) {
	t.Helper()

	oldRootCAs := rootCAs
	oldServerCert := serverCert
	t.Cleanup(func() {
		rootCAs = oldRootCAs
		serverCert = oldServerCert
	})

	rootPool, serverTLSCert, _ := buildServerConfigTLSConfigs(t, []net.IP{net.ParseIP("127.0.0.1")})
	serverConf := GetServerConfig(rootPool, &serverTLSCert)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("failed to create TLS listener from GetServerConfig: %v", err)
	}

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverHandshakeErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		serverHandshakeErr <- conn.(*tls.Conn).Handshake()
	}()

	return listener, serverHandshakeErr
}

func buildRawTLSClientHello(recordVersion uint16, clientHelloVersion uint16, cipherSuites []uint16) []byte {
	random := make([]byte, 32)
	for index := range random {
		random[index] = byte(index + 1)
	}

	cipherSuiteBytes := make([]byte, 0, len(cipherSuites)*2)
	for _, cipherSuite := range cipherSuites {
		cipherSuiteBytes = append(cipherSuiteBytes, byte(cipherSuite>>8), byte(cipherSuite))
	}

	compressionMethods := []byte{0x01, 0x00}
	clientHelloBody := make([]byte, 0, 2+32+1+2+len(cipherSuiteBytes)+len(compressionMethods)+2)
	clientHelloBody = append(clientHelloBody, byte(clientHelloVersion>>8), byte(clientHelloVersion))
	clientHelloBody = append(clientHelloBody, random...)
	clientHelloBody = append(clientHelloBody, 0x00)
	clientHelloBody = append(clientHelloBody, byte(len(cipherSuiteBytes)>>8), byte(len(cipherSuiteBytes)))
	clientHelloBody = append(clientHelloBody, cipherSuiteBytes...)
	clientHelloBody = append(clientHelloBody, compressionMethods...)
	clientHelloBody = append(clientHelloBody, 0x00, 0x00)

	handshake := make([]byte, 0, 4+len(clientHelloBody))
	handshake = append(handshake, 0x01)
	handshakeLength := len(clientHelloBody)
	handshake = append(handshake, byte(handshakeLength>>16), byte(handshakeLength>>8), byte(handshakeLength))
	handshake = append(handshake, clientHelloBody...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, byte(recordVersion>>8), byte(recordVersion))
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

func sendRawClientHello(serverAddr string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(payload); err != nil {
		return err
	}

	response := make([]byte, 1)
	_, _ = conn.Read(response)
	return nil
}

func assertServerHandshakeFailed(t *testing.T, serverHandshakeErr <-chan error, caseLabel string) {
	t.Helper()

	select {
	case err := <-serverHandshakeErr:
		if err == nil {
			t.Fatalf("expected server-side handshake to fail for %s", caseLabel)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for server-side handshake failure for %s", caseLabel)
	}
}
