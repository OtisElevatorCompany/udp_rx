// +build linux

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
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestCreateUDPSocket(t *testing.T) {
	err := CreateUDPSocket()
	if err != nil {
		log.Fatal("Failed to create a socket", err)
	}
}

func TestSendUDP(t *testing.T) {
	go handleUDPConn(t)
	srcip := "192.168.1.100"
	destip := "127.0.0.1"
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
		_, src, _ := ServerConn.ReadFromUDP(buf)
		if src.IP.String() != "192.168.1.100" {
			t.Errorf("src IP invalid: %s", src.IP.String())
		}
		if src.Port != 55553 {
			t.Errorf("src Port invalid %d", src.Port)
		}
		break
	}
	for i := 0; i < 11; i++ {
		if buf[i] != (byte)(10-i) {
			t.Errorf("Data invalid")
		}
	}
}

// UDP message handling correctness
// TestSendUDPZeroPayloadPreservesMetadata verifies that an empty payload still
// transmits the expected source IP and source port metadata.
func TestSendUDPZeroPayloadPreservesMetadata(t *testing.T) {
	received := make(chan *net.UDPAddr, 1)
	go func() {
		listenAddr := ":55556"
		serverAddr, _ := net.ResolveUDPAddr("udp", listenAddr)
		serverConn, _ := net.ListenUDP("udp", serverAddr)
		defer serverConn.Close()
		buf := make([]byte, 16)
		_, src, _ := serverConn.ReadFromUDP(buf)
		received <- src
	}()

	if err := SendUDP("192.168.1.100", "127.0.0.1", 55553, 55556, nil, 0); err != nil {
		t.Fatalf("SendUDP returned an unexpected error for zero payload: %v", err)
	}

	select {
	case src := <-received:
		if src.IP.String() != "192.168.1.100" {
			t.Fatalf("src IP invalid: %s", src.IP.String())
		}
		if src.Port != 55553 {
			t.Fatalf("src Port invalid %d", src.Port)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for zero-payload UDP packet")
	}
}

// TestSendUDPRejectsOversizedPayload verifies that payloads larger than the
// supported UDP message size are rejected with a size-related error.
func TestSendUDPRejectsOversizedPayload(t *testing.T) {
	oversizedPayload := make([]byte, 65508)
	err := SendUDP("192.168.1.100", "127.0.0.1", 55553, 55556, oversizedPayload, 0)
	if err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
	if !strings.Contains(err.Error(), "Message too large") {
		t.Fatalf("expected oversized payload error, got %v", err)
	}
}
