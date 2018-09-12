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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	certcreator "./cert_creator"
	log "github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

//Version is a constant that is this verion of the code, according to OTIS standards
const Version = "A1531825AAA"

//RemoteTLSPort is the port of the remote TLS server (also the port of the local TLS server)
const RemoteTLSPort = ":55554"

//static variable controlling how long to wait before a connection
//is considered by us to be 'timed out'
var connTimeoutVal float64 = 10

//tls config
var clientConf *tls.Config
var serverConf *tls.Config

//this mutex protects the TLS connection cache
var mutexMap = make(map[string]*sync.Mutex)
var mutexWriterMutex = &sync.Mutex{}

//connMap is a hashmap of strings (ip addresses in string form) to tls connection pointers
var connMap = make(map[string]*tls.Conn)
var lastConnFail = make(map[string]time.Time)

//command line effected variables
var profiling = false
var maxProfilingPackets = 1000
var netProfiling = false
var newdatalen = 4

//make an empty map decl for use when debug is on
var forwardMap map[string]int

// const startup arg values
const defaultListenAddr = ""

var confFilePath = "/etc/udp_rx/udp_rx_conf.json"
var defaultKeyPath = "/etc/udp_rx/udp_rx.key"
var defaultCertPath = "/etc/udp_rx/udp_rx.cert"
var defaultCACertPath = "/etc/udp_rx/ca.cert.pem"

var listenAddr, keyPath, certPath, caCertPath string

// conf file struct
type confFile struct {
	ListenAddr string `json:"listenAddr"`
	KeyPath    string `json:"keyPath"`
	CertPath   string `json:"certPath"`
	CaCertPath string `json:"caCertPath"`
}

func main() {
	fmt.Printf("Starting udp_rx at: %s\n", time.Now())

	//modify the defaults if we're on windows
	if isWindows() {
		modifyDefaultsWindows()
	}
	//get cand parse command line args
	versionFlag := flag.Bool("version", false, "Print the Version number and exit")
	logFlag := flag.Int("loglevel", 0, "level of logging. 0 is warn+, 1 is Info+, 2 is debug+")
	listenAddrFlag := flag.String("bindaddr", defaultListenAddr, "The IP address to bind the listening UDP socket to")
	cpuprofileFlag := flag.String("cpuprofile", "", "If specified writed a cpuprofile to the given filename")
	maxProfilingPacketsFlag := flag.Int("maxprofpackets", 1000, "the maximum number of packets allowed to be forwarded during CPU profiling")
	netProfilingFlag := flag.Bool("netprof", false, "turn on net profiling")
	lumberjackFlag := flag.Bool("lumberjack", false, "use lumberjack local file logging")
	//certificate flags
	keyPathFlag := flag.String("keypath", defaultKeyPath, "Override the default key path/name which is ./keys/server.key")
	certPathFlag := flag.String("certpath", defaultCertPath, "Override the default certificate path/name which is ./server.crt")
	caCertPathFlag := flag.String("cacert", defaultCACertPath, "Set the Certificate Authority Certificate to add to the trust")
	flag.Parse()
	//iniit the logger
	if *lumberjackFlag {
		fmt.Println("using lumberjack")
		log.SetOutput(&lumberjack.Logger{
			Filename:   "udp_rx.log",
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, // disabled by default
		})
	}
	fmt.Printf("Logger configured at: %s\n", time.Now())
	//if version flag, print version and exit
	if *versionFlag {
		fmt.Printf("Version is: %s\n", Version)
		os.Exit(0)
	}
	// load config file
	conf, err := parseConfig(confFilePath)
	if err == nil {
		setConfigValues(conf, listenAddrFlag, keyPathFlag, certPathFlag, caCertPathFlag)
	} else {
		log.Warn("Error parsing the config file. Error: ", err.Error())
	}
	// handle differences between command line args and config file
	//handles windows paths
	// if isWindows() {
	// 	*keyPathFlag = strings.Replace(*keyPathFlag, "/", "\\", -1)
	// 	*certPathFlag = strings.Replace(*certPathFlag, "/", "\\", -1)
	// }

	configLogger(logFlag)
	log.Warning("Starting udp_rx version: ", Version)

	//check if CPU profiling is on
	if *cpuprofileFlag != "" {
		f, err := os.Create(*cpuprofileFlag)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
		profiling = true
	}
	if *maxProfilingPacketsFlag != 1000 {
		log.Warning("overriding number of profiling packets to ", *maxProfilingPacketsFlag)
		maxProfilingPackets = *maxProfilingPacketsFlag
	}
	//set net profiling
	netProfiling = *netProfilingFlag
	if netProfiling {
		newdatalen = newdatalen + 8
	}

	//This will block until the year is > 1970
	log.Debug("Blocking until time > 1970")
	for {
		ctime := time.Now()
		if ctime.Year() > 1970 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Time sync done, unblocking")

	//load server cert as tls certs
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}
	//load the CA into the trusted store and return it for serverconf
	rootCAs := configureRootCAs(&caCertPath)
	//configure ssl
	clientConf = &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}

	serverConf = &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}

	//start listening on the UDP port in go routine
	go udpListener(&listenAddr)
	//start listening on TCP on main thread (blocking main from returning)
	tcpListener(&listenAddr)

}

func tcpListener(listenAddrFlag *string) {
	listenAddr := fmt.Sprintf("%s:55554", *listenAddrFlag)
	ln, err := tls.Listen("tcp", listenAddr, serverConf)
	if err != nil {
		log.Fatal(err)
	}
	//create UDP socket. On windows this actually does nothing...
	err = CreateUDPSocket()
	log.Debug("Created UDP socket")
	if err != nil {
		log.Fatal("Couldn't create udp socket", err)
	}
	defer ln.Close()
	log.Info("Ready to accept TLS connections...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error("error accepting new conn", err)
			continue
		}
		//put the connection into the mapping
		remoteAddr := strings.Split(conn.RemoteAddr().String(), ":")[0]
		if tlsconn, ok := conn.(*tls.Conn); ok {
			//fmt.Println("yes it's TLS")
			//fmt.Println(tlsconn)
			addConn(remoteAddr, tlsconn)
		}

		//go handle a connection in a gothread
		go handleConnection(conn, SendUDP)
	}
}

func udpListener(listenAddrFlag *string) {
	listenAddr := fmt.Sprintf("%s:55555", *listenAddrFlag)
	ServerAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Fatal("Couldn't bind udp listening socket")
	}
	//listen on the configured UDP port
	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ServerConn.Close()

	//loop variables
	buf := make([]byte, 1024)
	log.Info("Ready to accept connections...")
	for {
		n, src, err := ServerConn.ReadFromUDP(buf)
		//parse dest addr and dest port
		destAddr := fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		farport := (int(buf[4]) << 8) + int(buf[5])
		//debug logging
		if forwardMap != nil {
			fullAddr := fmt.Sprintf("%s:%d", destAddr, farport)
			//if nothing in forward map
			if forwardMap[fullAddr] == 0 {
				forwardMap[fullAddr] = 1
				log.Debug("Forwarding first message to ", fullAddr)
			} else {
				forwardMap[fullAddr] = forwardMap[fullAddr] + 1
				if forwardMap[fullAddr]%100 == 0 {
					log.Debug("Forwarded (another) 100 messages to ", fullAddr)
				}
			}
		}
		//end debug logging
		//if farport is reserved, don't continue processing, get the next packet
		if farport == 0 || farport == 1023 {
			log.Error("Got a bad dest port: ", farport)
			continue
		}
		//if there was an error here, don't try and forward the packet
		if err != nil {
			log.Error(err)
			continue
		}
		//catch if the dest is a local IP address
		isLocalHost := false
		ips, err := certcreator.GetIps()
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
				log.Error("Error sending to localhost")
			}
		} else {
			//otherwise forward to dest
			go forwardPacket(clientConf, destAddr, buf[4:n], src.Port, RemoteTLSPort)
		}

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

//ensures that there is a mutex to lock/unlock
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

func getConn(addr string, conf *tls.Config, remotePort string) (*tls.Conn, error) {
	//create a new mutex for this address if one doesn't exist
	checkMutexMapMutex(addr)
	//lock and defer closing
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	//also check
	conn := connMap[addr]
	if conn == nil {
		if time.Since(lastConnFail[addr]).Seconds() < connTimeoutVal {
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
		if forwardMap != nil {
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

func removeConn(addr string) {
	checkMutexMapMutex(addr)
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	delete(connMap, addr)
}

func configLogger(logFlag *int) error {
	log.SetFormatter(&log.JSONFormatter{})
	//newLogger()
	if *logFlag == 0 {
		log.SetLevel(log.WarnLevel)
		log.Warn("LogLevel set to warn")
	} else if *logFlag == 1 {
		log.SetLevel(log.InfoLevel)
		log.Info("LogLevel set to Info")
	} else {
		log.SetLevel(log.DebugLevel)
		log.Debug("LogLevel set to Debug")
		forwardMap = make(map[string]int)
	}
	return nil
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
		if profiling {
			counter++
			if counter > maxProfilingPackets {
				log.Warning("Stopping CPU profiling")
				pprof.StopCPUProfile()
				profiling = false
			}
		}
		//debug logging code
		if forwardMap != nil {
			//this string is in form [fromIpAddress]-[destination port]
			debugmapstring := fmt.Sprintf("%s-%d", rxip, destport)
			if forwardMap[debugmapstring] == 0 {
				forwardMap[debugmapstring] = 1
				log.Debug("Forwarding first message to ", debugmapstring)
			} else {
				forwardMap[debugmapstring] = forwardMap[debugmapstring] + 1
				if forwardMap[debugmapstring]%100 == 0 {
					log.Debug("Forwarded (another) 100 messages to ", debugmapstring)
				}
			}
		}
		//counter++
	}
}

func configureRootCAs(caCertPathFlag *string) *x509.CertPool {
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

func parseConfig(path string) (confFile, error) {
	jsonFile, err := os.Open(path)
	if err != nil {
		return confFile{}, err
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return confFile{}, err
	}
	var conf confFile
	err = json.Unmarshal(byteValue, &conf)
	return conf, nil
}

func setConfigValues(conf confFile, listAddrArg, keyPathArg, certPathArg, caCertPathArg *string) {
	// listen addr
	if *listAddrArg != defaultListenAddr {
		listenAddr = *listAddrArg
	} else if conf.ListenAddr != defaultListenAddr {
		listenAddr = conf.ListenAddr
	} else {
		listenAddr = defaultListenAddr
	}

	// key
	if *keyPathArg != defaultKeyPath {
		keyPath = *keyPathArg
	} else if conf.KeyPath != defaultKeyPath {
		keyPath = conf.KeyPath
	} else {
		keyPath = defaultKeyPath
	}

	// cert
	if *certPathArg != defaultCertPath {
		certPath = *certPathArg
	} else if conf.CertPath != defaultCertPath {
		certPath = conf.CertPath
	} else {
		certPath = defaultCertPath
	}

	// ca cert
	if *caCertPathArg != defaultCACertPath {
		caCertPath = *caCertPathArg
	} else if conf.CaCertPath != defaultCACertPath {
		caCertPath = conf.CaCertPath
	} else {
		caCertPath = defaultCACertPath
	}

}

func modifyDefaultsWindows() {
	confFilePath = "c:\\programdata\\udp_rx\\udp_rx_conf.windows.json"
	defaultKeyPath = "c:\\programdata\\udp_rx\\udp_rx.key"
	defaultCertPath = "c:\\programdata\\udp_rx\\udp_rx.cert"
	defaultCACertPath = "c:\\programdata\\udp_rx\\ca.cert.pem"
}
