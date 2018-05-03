package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

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

func main() {
	fmt.Printf("Starting UDPXR at: %s\n", time.Now())
	//iniit the logger
	log.SetOutput(&lumberjack.Logger{
		Filename:   "udp_xr.log",
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28,   //days
		Compress:   true, // disabled by default
	})
	fmt.Printf("Logger configured at: %s\n", time.Now())

	//get cand parse command line args
	logFlag := flag.Int("loglevel", 0, "level of logging. 0 is warn+, 1 is Info+, 2 is debug+")
	listenAddrFlag := flag.String("bindaddr", "", "The IP address to bind the listening UDP socket to")
	cpuprofileFlag := flag.String("cpuprofile", "", "write cpu profile to file")
	maxProfilingPacketsFlag := flag.Int("maxprofpackets", 1000, "the maximum number of packets allowed to be forwarded during CPU profiling")
	netProfilingFlag := flag.Bool("netprof", false, "turn on net profiling")
	flag.Parse()

	configLogger(logFlag)
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

	//configure ssl
	clientConf = &tls.Config{
		InsecureSkipVerify: true,
	}
	//load server certs
	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	serverConf = &tls.Config{
		Certificates: []tls.Certificate{cer},
	}

	//start listening on the UDP port in go routine
	go udpListener(listenAddrFlag)
	//start listening on TCP on main thread (blocking main from returning)
	tcpListener(listenAddrFlag)

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
		go handleConnection(conn)
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
		go forwardPacket(clientConf, destAddr, buf[4:n], src.Port)

	}
}

func forwardPacket(conf *tls.Config, addr string, data []byte, srcprt int) error {
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
		conn, err := getConn(addr, conf)
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
		return nil
	}
}

//ensures that there is a mutex to lock/unlock
func checkMutexMapMutex(addr string) {
	mutexWriterMutex.Lock()
	if mutexMap[addr] == nil {
		mutexMap[addr] = &sync.Mutex{}
	}
	mutexWriterMutex.Unlock()
}

func getConn(addr string, conf *tls.Config) (*tls.Conn, error) {
	//create a new mutex for this address if one doesn't exist
	checkMutexMapMutex(addr)
	//lock and defer closing
	mutexMap[addr].Lock()
	defer mutexMap[addr].Unlock()
	//also check
	conn := connMap[addr]
	if conn == nil {
		if time.Since(lastConnFail[addr]).Seconds() < connTimeoutVal {
			//log.Debug("not attempting to create new connection since timeout hasn't been reached since last failure")
			return nil, &connTimeoutError{"Connection hasn't timed out"}
		}
		log.Info("creating new cached connection for: ", addr)
		newconn, err := tls.Dial("tcp", addr+":55554", conf)
		if err != nil {
			log.Error(err)
			lastConnFail[addr] = time.Now()
			return nil, err
		}
		connMap[addr] = newconn
		//start recieving on this new connection too: (tls.Conn implements net.Conn interface)
		go handleConnection(newconn)
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

func handleConnection(conn net.Conn) {
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
		err = SendUDP(rxip, lcip, srcport, destport, buf[:mlength-2], counter)
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
		counter++
	}
}
