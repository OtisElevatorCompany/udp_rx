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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

//var cakeypath, certpath, keypath string
var cacertpath = "../keys/ca.crt"
var keypath = "../keys/server.key"
var certpath = "../keys/server.crt"

func modifyKeyPathsWindows() {
	if isWindows() {
		cacertpath = strings.Replace(cacertpath, "/", "\\", -1)
		//cakeypath = strings.Replace(cakeypath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
		certpath = strings.Replace(certpath, "/", "\\", -1)
	}
}

//TestCheckMutexMap checks the checkMutexMapMutex method
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

//TestGetConn checks the getConn method
func TestGetConn(t *testing.T) {
	//setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	//create a tls socket on localhost:
	ln := setupTLS(rootCAs)
	go handleIncomingTLS(ln)
	//end setup, start test

	clientConf := &tls.Config{
		//InsecureSkipVerify: true,
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
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	ln, _ := tls.Listen("tcp", ":55554", serverConf)
	return ln
}
func handleIncomingTLS(ln net.Listener) {
	for {
		fmt.Println("ready to accept connections...")
		conn, _ := ln.Accept()
		defer conn.Close()
		r := bufio.NewReader(conn)
		//buf := make([]byte, 1024)
		r.ReadLine()
		//io.ReadAtLeast(r, buf, 2)
		break
	}
}

//TestConnAddRemove checks the addConn and removeConn methods
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

//TestHandleConn tests the handleConn method
func TestHandleConn(t *testing.T) {
	//create a server to handle incoming connections
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
	//len
	barray[0] = 0
	barray[1] = 13
	//sourceport
	barray[2] = 0x11
	barray[3] = 0x93
	//destport
	barray[4] = 0x11
	barray[5] = 0x92
	for i := 0; i < 11; i++ {
		barray[6+i] = (byte)(10 - i)
	}
	conn.Write(barray)
	conn.Close()
}

//TestForwardPacket tests the forwardPacket method
func TestForwardPacket(t *testing.T) {
	//setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	//setup client config
	clientConf := &tls.Config{
		//InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	readyTLS := make(chan bool)
	go listenTLS(readyTLS)
	//block until readyTLS
	tlsReady := <-readyTLS
	log.Infof("tlsReady: %t", tlsReady)
	//time.Sleep(5 * time.Second)
	buf := make([]byte, 13)
	buf[0] = 0x11
	buf[1] = 0x92
	for i := 0; i < 11; i++ {
		buf[2+i] = (byte)(10 - i)
	}
	//make a header
	header := UDPRxHeader{
		MajorVersion: 1,
		MinorVersion: 0,
		PatchVersion: 0,
		PortNumber:   50300,
		DestIPAddr:   net.IPv4(127, 0, 0, 1),
	}
	//send it
	err = forwardPacket(clientConf, header, buf, 55554, ":55553")
	if err != nil {
		t.Error("Error forwarding packets")
	}
}
func listenTLS(readyTLS chan bool) {
	//setup certs
	modifyKeyPathsWindows()
	rootCAs := ConfigureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	lan, _ := tls.Listen("tcp", ":55553", serverConf)
	readyTLS <- true
	for {
		conn, _ := lan.Accept()
		defer conn.Close()
		r := bufio.NewReader(conn)
		//check length bytes
		lenbuf := make([]byte, 2)
		io.ReadAtLeast(r, lenbuf, 2)
		if lenbuf[0] != 0 || lenbuf[1] != 13 {
			panic("length wrong")
		}
		//check srcport bytes
		srcprtbuf := make([]byte, 2)
		io.ReadAtLeast(r, srcprtbuf, 2)
		if srcprtbuf[0] != 0xD9 || srcprtbuf[1] != 0x02 {
			panic("srcprt bytes wrong")
		}
		//check destport
		destprtbuf := make([]byte, 2)
		io.ReadAtLeast(r, destprtbuf, 2)
		if destprtbuf[0] != 0x11 || destprtbuf[1] != 0x92 {
			panic("destprt bytes wrong")
		}
		//finally, check data
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
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	doneChan := make(chan error)
	// override handleConnection
	handleConnectionFunc = mockHandleConnection
	//start the listener and send a message
	go TCPListener(&listenAddrSting, serverConf, doneChan)
	time.Sleep(time.Second * 3)
	sendTLSMessage(t, cer, rootCAs)
	//close the connection
	TCPSocketListener.Close()
	//get the done channel
	err = <-doneChan
	if err == nil {
		t.Error("Should have gotten an error")
	}
}
func sendTLSMessage(t *testing.T, cer tls.Certificate, rootCAs *x509.CertPool) {
	clientConf := &tls.Config{
		//InsecureSkipVerify: true,
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
	//conn.Close()
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
		//InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	doneChan := make(chan error)
	//start the UDP listener
	forwardPacketFunc = mockForwardPacket
	go UDPListener(&listenAddr, clientConf, doneChan)
	time.Sleep(time.Second * 3)
	//send a packet to the UDP listener
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
	//get the done channel
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
	//start
	buf[0] = 0x75
	//header version
	buf[1] = 0x01
	buf[2] = 0x02
	buf[3] = 0x03
	//port = 50300 in 2 bytes, big endian
	buf[4] = 0xC4
	buf[5] = 0x7C
	//ipv4
	buf[6] = 0x04
	//to 192.168.1.100
	buf[7] = 192
	buf[8] = 168
	buf[9] = 1
	buf[10] = 100
	//end
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
	//start
	buf[0] = 0x75
	//header version
	buf[1] = 0x01
	buf[2] = 0x02
	buf[3] = 0x03
	//port = 50300 in 2 bytes, big endian
	buf[4] = 0xC4
	buf[5] = 0x7C
	//ipv6
	buf[6] = 0x06
	//to 2600:8805:cc00:cc:ed0e:1b36:d342:474e
	destip := net.ParseIP("2600:8805:cc00:cc:ed0e:1b36:d342:474e")
	for i := 0; i < 16; i++ {
		buf[7+i] = destip[i]
	}
	//end
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
