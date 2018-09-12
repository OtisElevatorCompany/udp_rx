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
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

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
	var cacertpath, cakeypath, certpath, keypath string
	cacertpath = "./keys/ca.cert.pem"
	keypath = "./keys/server.key"
	certpath = "./keys/server.crt"
	if isWindows() {
		cacertpath = strings.Replace(cacertpath, "/", "\\", -1)
		cakeypath = strings.Replace(cakeypath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
		certpath = strings.Replace(certpath, "/", "\\", -1)
	}
	rootCAs := configureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	//create a tls socket on localhost:
	ln := setupTLS(rootCAs)
	go handleIncomingTLS(ln)
	//end setup, start test

	clientConf = &tls.Config{
		//InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	conn, err := getConn("127.0.0.1", clientConf, ":55554")
	if err != nil {
		t.Error("getConn returned an error")
	}
	conn.Write([]byte("Hello\n"))
}
func setupTLS(rootCAs *x509.CertPool) net.Listener {
	log.Warning("prepping incoming tls")
	fmt.Println("prepping to handle incoming TLS...")
	certpath := "./keys/server.crt"
	keypath := "./keys/server.key"
	if isWindows() {
		certpath = strings.Replace(certpath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
	}
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf = &tls.Config{
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
	addConn("192.168.1.100", nil)
	addConn("192.168.1.100", nil)
	addConn("192.168.1.101", nil)
	removeConn("192.168.1.100")
	removeConn("abc")
}

//TestLogConfig checks the logger configuration method
func TestLogConfig(t *testing.T) {
	t0 := 0
	t1 := 1
	t2 := 2
	configLogger(&t0)
	configLogger(&t1)
	configLogger(&t2)
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
	var cacertpath, cakeypath, certpath, keypath string
	cacertpath = "./keys/ca.cert.pem"
	keypath = "./keys/server.key"
	certpath = "./keys/server.crt"
	if isWindows() {
		cacertpath = strings.Replace(cacertpath, "/", "\\", -1)
		cakeypath = strings.Replace(cakeypath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
		certpath = strings.Replace(certpath, "/", "\\", -1)
	}
	rootCAs := configureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	//setup client config
	clientConf = &tls.Config{
		//InsecureSkipVerify: true,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	go listenTLS()
	buf := make([]byte, 13)
	buf[0] = 0x11
	buf[1] = 0x92
	for i := 0; i < 11; i++ {
		buf[2+i] = (byte)(10 - i)
	}
	forwardPacket(clientConf, "127.0.0.1", buf, 55554, ":55553")
}
func listenTLS() {
	//setup certs
	var cacertpath, cakeypath, certpath, keypath string
	cacertpath = "./keys/ca.cert.pem"
	keypath = "./keys/server.key"
	certpath = "./keys/server.crt"
	if isWindows() {
		cacertpath = strings.Replace(cacertpath, "/", "\\", -1)
		cakeypath = strings.Replace(cakeypath, "/", "\\", -1)
		keypath = strings.Replace(keypath, "/", "\\", -1)
		certpath = strings.Replace(certpath, "/", "\\", -1)
	}
	rootCAs := configureRootCAs(&cacertpath)
	cer, err := tls.LoadX509KeyPair(certpath, keypath)
	if err != nil {
		log.Fatal(err)
	}
	serverConf = &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	lan, _ := tls.Listen("tcp", ":55553", serverConf)
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

// TestParseConfig tests parsing the config file
func TestParseConfig(t *testing.T) {
	conf, err := parseConfig("./udp_rx_conf.json")
	if err != nil {
		t.Errorf("Couldn't parse config. Error: %s", err.Error())
		return
	}
	if conf.ListenAddr != "" {
		t.Error("Wrong default listen address")
	}
	if conf.KeyPath != "/etc/udp_rx/udp_rx.key" {
		t.Error("Wrong keypath")
	}
	if conf.CertPath != "/etc/udp_rx/udp_rx.cert" {
		t.Error("Wrong cert path")
	}
	if conf.CaCertPath != "/etc/udp_rx/ca.cert.pem" {
		t.Errorf("Wrong ca path. Path: %s", conf.CaCertPath)
	}
}

func TestModifyForWindows(t *testing.T) {
	confFilePath = ""
	defaultKeyPath = ""
	defaultCertPath = ""
	defaultCACertPath = ""
	modifyDefaultsWindows()
	if confFilePath != "c:\\programdata\\udp_rx\\udp_rx_conf.windows.json" {
		t.Errorf("Error with windows conf path. Path: %s", confFilePath)
	}
	if defaultKeyPath != "c:\\programdata\\udp_rx\\udp_rx.key" {
		t.Errorf("Error with windows key path. Path: %s", defaultKeyPath)
	}
	if defaultCertPath != "c:\\programdata\\udp_rx\\udp_rx.cert" {
		t.Errorf("Error with windows cert path. Path: %s", defaultCertPath)
	}
	if defaultCACertPath != "c:\\programdata\\udp_rx\\ca.cert.pem" {
		t.Errorf("Error with windows ca cert path. Path: %s", defaultCACertPath)
	}
}

func TestSetConfigValues(t *testing.T) {
	// make a confFile with some known values
	conf := confFile{
		ListenAddr: "abc",
		KeyPath:    "def",
		CertPath:   "foo",
		CaCertPath: defaultCACertPath,
	}
	defLisAddr := defaultListenAddr
	changedCertArg := "foobar"
	setConfigValues(conf, &defLisAddr, &defaultKeyPath, &changedCertArg, &defaultCACertPath)
	// listen addr and key path should be set from conf object
	if listenAddr != "abc" {
		t.Errorf("listen address is wrong. Value: %s", listenAddr)
	}
	if keyPath != "def" {
		t.Errorf("keypath is wrong. Value: %s", keyPath)
	}
	// cert arg should be set from command line arg
	if certPath != "foobar" {
		t.Errorf("certpath is wrong. Value: %s", certPath)
	}
	// CaCertPath should be default
	if caCertPath != defaultCACertPath {
		t.Errorf("ca certpath shouldn't have changed. Value: %s", caCertPath)
	}
}
