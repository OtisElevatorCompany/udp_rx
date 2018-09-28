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

// Package udprxlib is the driver for udprx
package udprxlib

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	certcreator "../cert_creator"
	log "github.com/sirupsen/logrus"
)

var cpuProfiling = false
var netProfiling = false
var maxProfilingPackets = 1000
var newdatalen = 4

// ForwardMap should be set to not nil if debug is on
var ForwardMap map[string]int

//this mutex protects the TLS connection cache
var mutexMap = make(map[string]*sync.Mutex)
var mutexWriterMutex = &sync.Mutex{}

//connMap is a hashmap of strings (ip addresses in string form) to tls connection pointers
var connMap = make(map[string]*tls.Conn)
var lastConnFail = make(map[string]time.Time)

//RemoteTLSPort is the port of the remote TLS server (also the port of the local TLS server)
var RemoteTLSPort = ":55554"

// ConnTimeoutVal is a variable controlling how long to wait (in seconds)
// before a connection is considered by us to be 'timed out'
var ConnTimeoutVal float64 = 10

// TCPSocketListener is the tls socket listener
var TCPSocketListener net.Listener
var handleConnectionFunc = handleConnection

// TCPListener is the tcp socket loop for udprx inbound connections
func TCPListener(listenAddrFlag *string, serverConf *tls.Config, done chan error) {
	listenAddr := fmt.Sprintf("%s:55554", *listenAddrFlag)
	ln, err := tls.Listen("tcp", listenAddr, serverConf)
	if err != nil {
		log.Error(err)
		done <- err
		return
	}
	TCPSocketListener = ln
	//create UDP socket. On windows this actually does nothing...
	err = CreateUDPSocket()
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Couldn't create udp socket")
		done <- err
		return
	}
	log.Debug("Created UDP socket")
	defer ln.Close()
	log.Info("Ready to accept TLS connections...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.WithFields(
				log.Fields{
					"error": err,
				}).Error("Error listening for TLS connections. Terminating TCPListener thread")
			done <- err
			return
		}
		//put the connection into the mapping
		remoteAddr := strings.Split(conn.RemoteAddr().String(), ":")[0]
		if tlsconn, ok := conn.(*tls.Conn); ok {
			addConn(remoteAddr, tlsconn)
		}

		//go handle a connection in a gothread
		go handleConnectionFunc(conn, SendUDP)
	}
}

// UDPSocketListener is the udp socket listener
var UDPSocketListener *net.UDPConn
var forwardPacketFunc = forwardPacket

// UDPListener is the udp local listener for outbound connections
func UDPListener(listenAddrFlag *string, clientConf *tls.Config, done chan error) {
	listenAddr := fmt.Sprintf("%s:55555", *listenAddrFlag)
	ServerAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Couldn't bind udp listening socket")
		done <- err
		return
	}
	//listen on the configured UDP port
	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	UDPSocketListener = ServerConn
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Couldn't Listen to UDP")
		done <- err
		return
	}
	defer ServerConn.Close()

	//loop variables
	buf := make([]byte, 1024)
	log.Info("Ready to accept connections...")
	for {
		n, src, err := ServerConn.ReadFromUDP(buf)
		if err != nil {
			log.WithFields(
				log.Fields{
					"error": err,
				}).Error("Error reading from UDP port. Terminating UDP thread.")
			done <- err
			return
		}
		//parse dest addr and dest port
		destAddr := fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		farport := (int(buf[4]) << 8) + int(buf[5])
		//debug logging
		if ForwardMap != nil {
			fullAddr := fmt.Sprintf("%s:%d", destAddr, farport)
			//if nothing in forward map
			if ForwardMap[fullAddr] == 0 {
				ForwardMap[fullAddr] = 1
				log.Debug("Forwarding first message to ", fullAddr)
			} else {
				ForwardMap[fullAddr] = ForwardMap[fullAddr] + 1
				if ForwardMap[fullAddr]%100 == 0 {
					log.Debug("Forwarded (another) 100 messages to ", fullAddr)
				}
			}
		}
		//end debug logging
		//if farport is reserved, don't continue processing, get the next packet
		if farport == 0 || farport == 1023 {
			log.WithFields(
				log.Fields{
					"error":     err,
					"dest port": farport,
				}).Error("Got a bad dest port")
			continue
		}
		//if there was an error here, don't try and forward the packet
		if err != nil {
			log.WithFields(
				log.Fields{
					"error": err,
				}).Error("Error in packet, not forwarding")
			continue
		}
		//catch if the dest is a local IP address
		isLocalHost := false
		ips, err := certcreator.GetIps()
		if err != nil {
			log.WithFields(
				log.Fields{
					"error": err,
				}).Error("Error getting local ips for localhost checking")
			continue
		}
		//build an ipv4 address
		destip := net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		for _, ip := range ips {
			ipstring := ip.String()
			_ = ipstring
			if ip.String() == destip {
				isLocalHost = true
				break
			}
		}
		// if !isLocalHost && destip == net.IPv4(127, 0, 0, 1).String() {
		// 	isLocalHost = true
		// }
		if isLocalHost {
			//skip forward packet and go straight to
			err = SendUDP("127.0.0.1", destip, uint(src.Port), uint(farport), buf[6:], 0)
			if err != nil {
				log.WithFields(
					log.Fields{
						"error": err,
					}).Error("Error sending to localhost")
			}
		} else {
			//otherwise forward to dest
			go forwardPacketFunc(clientConf, destAddr, buf[4:n], src.Port, RemoteTLSPort)
		}

	}
}

// ConfigureRootCAs creats a new systemcertpool and adds a cert
// from a pem encoded cert file to it
func ConfigureRootCAs(caCertPathFlag *string) *x509.CertPool {
	//also load as bytes for x509
	// Read in the cert file
	x509certs, err := ioutil.ReadFile(*caCertPathFlag)
	if err != nil {
		log.Fatalf("Failed to append certificate to RootCAs: %v", err)
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	//append the local cert to the in-memory system CA pool
	if ok := rootCAs.AppendCertsFromPEM(x509certs); !ok {
		log.Warning("No certs appended, using system certs only")
	}
	return rootCAs
}

// EnableNetProfiling turns on network profiling features
func EnableNetProfiling(numPackets int) {
	newdatalen = newdatalen + 8
	if cpuProfiling {
		log.Warning("You should not cpu and network profile at the same time!")
	}
	netProfiling = true
	maxProfilingPackets = numPackets
}

// EnableCPUProfiling turns on cpu profiling
func EnableCPUProfiling(numPackets int, profileFilePath *string) {
	if netProfiling {
		log.Warning("You should not cpu and network profile at the same time!")
	}
	cpuProfiling = true
	maxProfilingPackets = numPackets
	f, err := os.Create(*profileFilePath)
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)

	log.Warning("CPU profiling started")
}

// StopThreads stops the TCP and UDP listeners and closes all connections
func StopThreads() {
	// close sockets
	TCPSocketListener.Close()
	UDPSocketListener.Close()
	// close all open connections
	for _, conn := range connMap {
		conn.Close()
	}
	connMap = make(map[string]*tls.Conn)
}

func addConn(addr string, conn *tls.Conn) {
	//create a new mutex for this address if one doesn't exist
	checkMutexMapMutex(addr)
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	//check if there's already a connection, if there is, do nothing, it should be OK
	existingConn := connMap[addr]
	if existingConn == nil {
		connMap[addr] = conn
	}
}

func checkMutexMapMutex(addr string) bool {
	createdMutex := false
	mutexWriterMutex.Lock()
	defer mutexWriterMutex.Unlock()
	if mutexMap[addr] == nil {
		mutexMap[addr] = &sync.Mutex{}
		createdMutex = true
	}
	return createdMutex
}

func handleConnection(conn net.Conn, sender sendUDPFn) {
	defer conn.Close()
	//create a a reader for the connection
	r := bufio.NewReader(conn)
	counter := 0
	lastLoopEOF := false
	for {
		//create buffers
		buf := make([]byte, 1024)
		lenbytes := make([]byte, 2)
		srcprtbytes := make([]byte, 2)
		destportbytes := make([]byte, 2)

		//get the top 2 bytes and put them into lenbytes
		//if there's a non EOF error, return (kills the connection), otherwise EOF is OK, restart loop
		_, err := io.ReadAtLeast(r, lenbytes, 2)
		if err != nil {
			if err != io.EOF {
				log.Error(err)
				return
			} else if lastLoopEOF {
				//if the last loop was also an immediate eof, return
				return
			} else {
				//set double immediate lastLoopEOF flag
				lastLoopEOF = true
				continue
			}
		}
		//if we didn't hit an EOF, we have a packet, set lastLoopEOF to false
		lastLoopEOF = false
		//set message length
		mlength := (int(lenbytes[0]) << 8) + int(lenbytes[1])
		//get the 2 srcport bytes from the front and combine them
		_, err = io.ReadAtLeast(r, srcprtbytes, 2)
		if err != nil {
			log.Error(err)
			return
		}
		//check for reserved ports
		srcport := (uint(srcprtbytes[0]) << 8) + uint(srcprtbytes[1])
		if srcport < 0 || srcport == 0 || srcport == 1023 {
			return
		}
		//get the 2 destport bytes from the front and combine them
		_, err = io.ReadAtLeast(r, destportbytes, 2)
		if err != nil {
			log.Error(err)
			return
		}
		//check for reserved ports (again)
		destport := (uint(destportbytes[0]) << 8) + uint(destportbytes[1])
		if destport < 0 || destport == 0 || destport == 1023 {
			log.Error("invalid destination port number: ", destport)
			return
		}
		//get the rest of the data. It's mlength-2 because we already got destport
		_, err2 := io.ReadAtLeast(r, buf, mlength-2)
		if err2 != nil {
			log.Error(err)
			return
		}
		//get the remote (sender) ip and port
		rxipandport := conn.RemoteAddr().String()
		//get the ip and port the sender connected to (might be multiple)
		localipandport := conn.LocalAddr().String()
		//split out just the IPs into a string
		rxip := strings.Split(rxipandport, ":")[0]
		lcip := strings.Split(localipandport, ":")[0]
		//_ = lcip
		//if netprofiling
		if netProfiling {
			for index, element := range getTimeBytes() {
				buf[mlength-2+index] = element
				//fmt.Printf("udpx - %d\n", element)
			}
			mlength = mlength + 8
		}
		//craft and send a UDP packet
		err = sender(rxip, lcip, srcport, destport, buf[:mlength-2], counter)
		if err != nil {
			log.Error(err)
			return
		}
		//profiling
		if cpuProfiling {
			counter++
			if counter > maxProfilingPackets {
				log.Warning("Stopping CPU profiling")
				pprof.StopCPUProfile()
				cpuProfiling = false
			}
		}
		//debug logging code
		if ForwardMap != nil {
			//this string is in form [fromIpAddress]-[destination port]
			debugmapstring := fmt.Sprintf("%s-%d", rxip, destport)
			if ForwardMap[debugmapstring] == 0 {
				ForwardMap[debugmapstring] = 1
				log.Debug("Forwarding first message to ", debugmapstring)
			} else {
				ForwardMap[debugmapstring] = ForwardMap[debugmapstring] + 1
				if ForwardMap[debugmapstring]%100 == 0 {
					log.Debug("Forwarded (another) 100 messages to ", debugmapstring)
				}
			}
		}
		//counter++
	}
}

func forwardPacket(conf *tls.Config, addr string, data []byte, srcprt int, remoteTLSPort string) error {
	//prepend the number of bytes into
	lenbytes := intToBytes(len(data))
	if netProfiling {
		lenbytes = intToBytes(len(data) + 8)
	}
	srcbytes := intToBytes(srcprt)
	newdata := make([]byte, len(data)+newdatalen)
	//put the mlength
	newdata[0] = lenbytes[0]
	newdata[1] = lenbytes[1]
	//put the srcport
	newdata[2] = srcbytes[0]
	newdata[3] = srcbytes[1]
	//copy the data over
	copy(newdata[4:], data)
	//if we're net profiling, add the timestamp
	if netProfiling {
		copy(newdata[4+len(data):], getTimeBytes())
	}
	try := 0
	for {
		//get a cached conn or create a new one
		conn, err := getConn(addr, conf, remoteTLSPort)
		if err != nil {
			_, ok := err.(*connTimeoutError)
			if !ok {
				log.Error(err)
			}
			return err
		}
		n, err := conn.Write(newdata)
		if err != nil {
			log.Error(n, err)
			if try < 3 {
				log.Debug("removing old connmap")
				removeConn(addr)
				try = try + 1
				continue
			} else {
				return err
			}
		}
		log.Debug("sent a packet")
		return nil
	}
}

func getConn(addr string, conf *tls.Config, remotePort string) (*tls.Conn, error) {
	//create a new mutex for this address if one doesn't exist
	checkMutexMapMutex(addr)
	//lock and defer closing
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	//also check
	conn := connMap[addr]
	if conn == nil {
		if time.Since(lastConnFail[addr]).Seconds() < ConnTimeoutVal {
			return nil, &connTimeoutError{"Connection hasn't timed out"}
		}
		log.Info("creating new cached connection for: ", addr)
		newconn, err := tls.Dial("tcp", addr+remotePort, conf)
		if err != nil {
			log.Error(err)
			lastConnFail[addr] = time.Now()
			return nil, err
		}
		connMap[addr] = newconn
		//start recieving on this new connection too: (tls.Conn implements net.Conn interface)
		go handleConnection(newconn, SendUDP)
		//debug code
		if ForwardMap != nil {
			connstate := newconn.ConnectionState()
			log.WithFields(log.Fields{
				"Version":                 connstate.Version,
				"Handshake complete":      connstate.HandshakeComplete,
				"CipherSuite":             connstate.CipherSuite,
				"NegotiatedProto":         connstate.NegotiatedProtocol,
				"NegotiatedProtoIsMutual": connstate.NegotiatedProtocolIsMutual,
			}).Debug("Connection Information:")
		}
		return newconn, nil
	}
	return conn, nil
}

func removeConn(addr string) {
	checkMutexMapMutex(addr)
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	delete(connMap, addr)
}
