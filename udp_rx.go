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
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	"./udprxlib"

	log "github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Version is a constant that is this verion of the code, according to OTIS standards
const Version = "A1131825AAB"

// RemoteTLSPort is the port of the remote TLS server (also the port of the local TLS server)
const RemoteTLSPort = ":55554"

// tls config
var clientConf *tls.Config
var serverConf *tls.Config

// const startup arg values
const defaultListenAddr = ""

var confFilePath = "/etc/udp_rx/udp_rx_conf.json"
var defaultKeyPath = "/etc/udp_rx/udp_rx.key"
var defaultCertPath = "/etc/udp_rx/udp_rx.crt"
var defaultCACertPath = "/etc/udp_rx/ca.crt"
var defaultLogPath = "/var/log/udp_rx.log"

var listenAddr, keyPath, certPath, caCertPath string

func main() {
	fmt.Printf("Starting udp_rx at: %s\n", time.Now())

	// modify the defaults if we're on windows
	if isWindows() {
		modifyDefaultsWindows()
	}
	// get and parse command line args
	versionFlag := flag.Bool("version", false, "Print the Version number and exit")
	logFlag := flag.Int("loglevel", 0, "level of logging. 0 is warn+, 1 is Info+, 2 is debug+")
	listenAddrFlag := flag.String("bindaddr", defaultListenAddr, "The IP address to bind the listening UDP socket to")
	cpuprofileFlag := flag.String("cpuprofile", "", "If specified writed a cpuprofile to the given filename")
	maxProfilingPacketsFlag := flag.Int("maxprofpackets", 1000, "the maximum number of packets allowed to be forwarded during CPU profiling")
	netProfilingFlag := flag.Bool("netprof", false, "turn on net profiling")
	lumberjackFlag := flag.Bool("lumberjack", false, "use lumberjack local file logging")
	logPathFlag := flag.String("logpath", defaultLogPath, "the path to log to")
	// configuration filepath override
	confFileFlag := flag.String("conf", confFilePath, "Override the default configuration filepath")
	// certificate flags
	keyPathFlag := flag.String("keypath", defaultKeyPath, "Override the default key path/name which is ./keys/server.key")
	certPathFlag := flag.String("certpath", defaultCertPath, "Override the default certificate path/name which is ./server.crt")
	caCertPathFlag := flag.String("cacert", defaultCACertPath, "Set the Certificate Authority Certificate to add to the trust")
	flag.Parse()
	// init the logger
	if *lumberjackFlag {
		fmt.Println("using lumberjack")
		log.SetOutput(&lumberjack.Logger{
			Filename:   *logPathFlag,
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28,   // days
			Compress:   true, // disabled by default
		})
	}
	fmt.Printf("Logger configured at: %s\n", time.Now())
	// if version flag, print version and exit
	if *versionFlag {
		fmt.Printf("Version is: %s\n", Version)
		os.Exit(0)
	}
	// load config file
	conf, err := udprxlib.ParseConfig(*confFileFlag)
	if err == nil {
		setConfigValues(&conf, listenAddrFlag, keyPathFlag, certPathFlag, caCertPathFlag)
	} else {
		log.Warn("Error parsing the config file. Error: ", err.Error())
		setConfigValues(nil, listenAddrFlag, keyPathFlag, certPathFlag, caCertPathFlag)
	}

	configLogger(logFlag)
	log.Warning("Starting udp_rx version: ", Version)

	// check if CPU profiling is on
	if *cpuprofileFlag != "" {
		log.Warning("Turning on cpu profling...")
		udprxlib.EnableCPUProfiling(*maxProfilingPacketsFlag, cpuprofileFlag)
	}
	// set net profiling
	if *netProfilingFlag {
		if *maxProfilingPacketsFlag != 1000 {
			log.Warning("overriding number of profiling packets to ", *maxProfilingPacketsFlag)
		}
		udprxlib.EnableNetProfiling(*maxProfilingPacketsFlag)
	}

	// This will block until the year is > 1970
	log.Debug("Blocking until time > 1970")
	for {
		ctime := time.Now()
		if ctime.Year() > 1970 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Time sync done, unblocking")

	// load server cert as tls certs
	log.Debug("keypath: ", certPath)
	log.Debug("certpath: ", keyPath)
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}
	// load the CA into the trusted store and return it for serverconf
	rootCAs := udprxlib.ConfigureRootCAs(&caCertPath)
	// configure ssl
	clientConf = &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	serverConf = udprxlib.GetServerConfig(rootCAs, &cer)

	// start listening on the UDP port in go routine
	udpListenerDone := make(chan error, 1)
	go udprxlib.UDPListener(&listenAddr, clientConf, udpListenerDone)
	// start listening on TCP on main thread (blocking main from returning)
	tcpListenerDone := make(chan error, 1)
	udprxlib.TCPListener(&listenAddr, serverConf, tcpListenerDone)
}

func configLogger(logFlag *int) error {
	log.SetFormatter(&log.JSONFormatter{})
	if *logFlag == 0 {
		log.SetLevel(log.WarnLevel)
		log.Warn("LogLevel set to warn")
	} else if *logFlag == 1 {
		log.SetLevel(log.InfoLevel)
		log.Info("LogLevel set to Info")
	} else {
		log.SetLevel(log.DebugLevel)
		log.Debug("LogLevel set to Debug")
		udprxlib.ForwardMap = make(map[string]int)
	}
	return nil
}

func setConfigValues(conf *udprxlib.ConfFile, listAddrArg, keyPathArg, certPathArg, caCertPathArg *string) {
	// precedence is: command line arg -> config file -> program default
	// listen addr
	if *listAddrArg != defaultListenAddr {
		listenAddr = *listAddrArg
	} else if conf != nil && conf.ListenAddr != defaultListenAddr {
		listenAddr = conf.ListenAddr
	} else {
		listenAddr = defaultListenAddr
	}

	// key
	if *keyPathArg != defaultKeyPath {
		keyPath = *keyPathArg
	} else if conf != nil && conf.KeyPath != defaultKeyPath {
		keyPath = conf.KeyPath
	} else {
		keyPath = defaultKeyPath
	}

	// cert
	if *certPathArg != defaultCertPath {
		certPath = *certPathArg
	} else if conf != nil && conf.CertPath != defaultCertPath {
		certPath = conf.CertPath
	} else {
		certPath = defaultCertPath
	}

	// ca cert
	if *caCertPathArg != defaultCACertPath {
		caCertPath = *caCertPathArg
	} else if conf != nil && conf.CaCertPath != defaultCACertPath {
		caCertPath = conf.CaCertPath
	} else {
		caCertPath = defaultCACertPath
	}

}

func modifyDefaultsWindows() {
	confFilePath = "c:\\programdata\\udp_rx\\udp_rx_conf.windows.json"
	defaultKeyPath = "c:\\programdata\\udp_rx\\udp_rx.key"
	defaultCertPath = "c:\\programdata\\udp_rx\\udp_rx.crt"
	defaultCACertPath = "c:\\programdata\\udp_rx\\ca.crt"
	defaultLogPath = "c:\\programdata\\udp_rx\\udp_rx.log"
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
