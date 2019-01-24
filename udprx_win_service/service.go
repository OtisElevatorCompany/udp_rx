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

var confFilePath = "c:\\programdata\\udp_rx\\udp_rx_conf.json"
var defaultKeyPath = "c:\\programdata\\udp_rx\\udp_rx.key"
var defaultCertPath = "c:\\programdata\\udp_rx\\udp_rx.crt"
var defaultCACertPath = "c:\\programdata\\udp_rx\\ca.crt"

// const startup arg values
const defaultListenAddr = ""

// config values
var listenAddr, keyPath, certPath, caCertPath string

// tls configs
var clientConf *tls.Config
var serverConf *tls.Config

var elog debug.Log

type myservice struct{}

func startNetListeners() (chan error, chan error) {
	// setup error channels
	udpListenerChan := make(chan error, 1)
	tcpListenerChan := make(chan error, 1)
	// start the threads
	go udprxlib.UDPListener(&listenAddr, clientConf, udpListenerChan)
	go udprxlib.TCPListener(&listenAddr, serverConf, tcpListenerChan)
	return udpListenerChan, tcpListenerChan
}

func (m *myservice) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	// setup service
	// accept stop means interactively being stopped by a user/the os
	// accept shutdown means responding to a system shutdown event
	// accept pause and continue means interactive pause and continue from user/the os
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	elog.Info(startArgs, strings.Join(args, "-"))
	// setup error channels
	udpListenerChan, tcpListenerChan := startNetListeners()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		// block until one of these cases can run
		select {
		case err := <-udpListenerChan:
			elog.Error(udpThreadStopped, fmt.Sprintf("UDP Thread Stopped. Error: %s", err.Error()))
			udprxlib.StopThreads()
			changes <- svc.Status{State: svc.Stopped, Accepts: cmdsAccepted}
		case err := <-tcpListenerChan:
			elog.Error(tcpThreadStopped, fmt.Sprintf("TCP Thread Stopped. Error: %s", err.Error()))
			udprxlib.StopThreads()
			changes <- svc.Status{State: svc.Stopped, Accepts: cmdsAccepted}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				udprxlib.StopThreads()
				// This breaks from the case and loop, going to StopPending
				break loop
			case svc.Pause:
				udprxlib.StopThreads()
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				// tick = slowtick
			case svc.Continue:
				udpListenerChan, tcpListenerChan = startNetListeners()
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				// tick = fasttick
			default:
				elog.Error(unexpectedControlRequest, fmt.Sprintf("unexpected control request #%d", c))
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
	elog.Info(parsingConfigFile, "parsing udprx configuration")
	// check the default location for the file first
	if _, err := os.Stat(confFilePath); os.IsNotExist(err) {
		elog.Info(configurationFileError, "Couldn't find config file in programdata\\udp_rx. Trying locally")
		if _, err := os.Stat(confFilePath); os.IsNotExist(err) {
			elog.Info(configurationFileError, "Couldn't find config file locally. Running with defaults")
			fmt.Println("File does not exist")
		}
	}
	conf, err := udprxlib.ParseConfig(confFilePath)
	setConfigValues(conf)
	// load keys
	// load server cert as tls certs
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
	serverConf = udprxlib.GetServerConfig(rootCAs, &cer)
	// config done
	elog.Info(startingService, fmt.Sprintf("starting %s service", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}
	err = run(name, &myservice{})
	if err != nil {
		elog.Error(serviceFailed, fmt.Sprintf("%s service failed: %v", name, err))
		return
	}
	elog.Info(serviceStopped, fmt.Sprintf("%s service stopped", name))
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
