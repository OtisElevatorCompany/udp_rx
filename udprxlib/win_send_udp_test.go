// +build windows

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
	"net"
	"testing"
)

func TestCreateUDPSocket(t *testing.T) {
	err := CreateUDPSocket()
	if err != nil {
		t.Errorf("Failed to create a socket")
	}
}

func TestSendUDP(t *testing.T) {
	go handleUDPConn(t)
	srcip := "192.168.1.100"
	destip := "192.168.1.101"
	var srcprt uint = 55553
	var destprt uint = 55552
	databuf := make([]byte, 11)
	for i := 0; i < 11; i++ {
		databuf[i] = (byte)(10 - i)
	}
	SendUDP(srcip, destip, srcprt, destprt, databuf, 0)
}
func handleUDPConn(t *testing.T) {
	listenAddr := ":55552"
	ServerAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
	ServerConn, _ := net.ListenUDP("udp", ServerAddr)
	defer ServerConn.Close()
	buf := make([]byte, 1024)
	for {
		ServerConn.ReadFromUDP(buf)
		break
	}
	if buf[0] != 192 || buf[1] != 168 || buf[2] != 1 || buf[3] != 100 {
		t.Errorf("Invalid src ip")
	}
	if buf[4] != 0xD9 || buf[5] != 0x01 {
		t.Errorf("Invalid src prt")
	}
	for i := 0; i < 11; i++ {
		if buf[6+i] != (byte)(10-i) {
			t.Errorf("Data invalid")
		}
	}
}
