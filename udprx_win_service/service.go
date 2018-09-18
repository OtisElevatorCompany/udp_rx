// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"../udprxlib"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var confFilePath = "c:\\programdata\\udp_rx\\udp_rx_conf.windows.json"
var defaultKeyPath = "c:\\programdata\\udp_rx\\udp_rx.key"
var defaultCertPath = "c:\\programdata\\udp_rx\\udp_rx.cert"
var defaultCACertPath = "c:\\programdata\\udp_rx\\ca.cert.pem"

// const startup arg values
const defaultListenAddr = ""

// config values
var listenAddr, keyPath, certPath, caCertPath string

//tls configs
var clientConf *tls.Config
var serverConf *tls.Config

var elog debug.Log

type myservice struct{}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	// setup service
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	fasttick := time.Tick(500 * time.Millisecond)
	slowtick := time.Tick(2 * time.Second)
	tick := fasttick
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	elog.Info(1, strings.Join(args, "-"))
	// setup error channels
	udpListenerChan := make(chan error, 1)
	tcpListenerChan := make(chan error, 1)
	// start the threads
	go udprxlib.UDPListener(&listenAddr, clientConf, udpListenerChan)
	go udprxlib.TCPListener(&listenAddr, serverConf, tcpListenerChan)
loop:
	for {
		// block until one of these cases can run
		select {
		case <-tick:
			//beep()
			elog.Info(1, "beep")
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// This breaks from the CASE, and then goes to LOOP
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				tick = slowtick
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				tick = fasttick
			default:
				elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
	}
	defer elog.Close()
	elog.Info(1, "parsing udprx configuration")
	// check the default location for the file first
	if _, err := os.Stat(confFilePath); os.IsNotExist(err) {
		elog.Info(configurationFileError, "Couldn't find config file in programdata\\udp_rx. Trying locally")
		if _, err := os.Stat("udp_rx_conf.windows.json"); os.IsNotExist(err) {
			elog.Info(configurationFileError, "Couldn't find config file locally. Running with defaults")
			fmt.Println("File does not exist")
		}
	}
	conf, err := udprxlib.ParseConfig(confFilePath)
	setConfigValues(conf)
	// load keys
	//load server cert as tls certs
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		elog.Error(deviceKeyCertLoading, "Error loading device keys/certs")
		return
	}
	// configure ssl
	rootCAs := udprxlib.ConfigureRootCAs(&caCertPath)
	// clientConf
	clientConf = &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cer},
	}
	// serverConf
	serverConf = &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCAs,
	}
	// config done
	elog.Info(1, fmt.Sprintf("starting %s service", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	err = run(name, &myservice{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", name))
}

func setConfigValues(conf udprxlib.ConfFile) {
	// listen addr
	if conf.ListenAddr != defaultListenAddr {
		listenAddr = conf.ListenAddr
	} else {
		listenAddr = defaultListenAddr
	}

	// key
	if conf.KeyPath != defaultKeyPath {
		keyPath = conf.KeyPath
	} else {
		keyPath = defaultKeyPath
	}

	// cert
	if conf.CertPath != defaultCertPath {
		certPath = conf.CertPath
	} else {
		certPath = defaultCertPath
	}

	// ca cert
	if conf.CaCertPath != defaultCACertPath {
		caCertPath = conf.CaCertPath
	} else {
		caCertPath = defaultCACertPath
	}

}
