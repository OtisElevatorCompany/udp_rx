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
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// CreateUDPSocket is here to provide x-platform compat. Always returns nil, does nothing
func CreateUDPSocket() error {
	log.Info("Creating Windows UDP socket")
	return nil
}

// SendUDP takes in the associated data and puts a UDP packet on the wire
func SendUDP(srcipstr string, destipstr string, srcprt uint, destprt uint, data []byte, counter int) error {
	// parse ip strings
	srcip, _, err := ParseIps(srcipstr, destipstr)
	if err != nil {
		log.Error("error in parse ips")
		return err
	}
	// dial and connect to localhost
	ServerAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", destipstr, destprt))
	if err != nil {
		log.Error("Error resolving localhost - this should never happen")
		return err
	}
	Conn, err := net.DialUDP("udp", nil, ServerAddr)
	if err != nil {
		log.Error("Error dialing localhost")
		return err
	}
	defer Conn.Close()
	// prepend srcip and srcport to data and call it newdata
	newdata := make([]byte, len(data)+6)
	if len(srcip) > 4 {
		newdata[0] = srcip[12]
		newdata[1] = srcip[13]
		newdata[2] = srcip[14]
		newdata[3] = srcip[15]
	} else {
		newdata[0] = srcip[0]
		newdata[1] = srcip[1]
		newdata[2] = srcip[2]
		newdata[3] = srcip[3]
	}
	srcprtbytes := uintToBytes(srcprt)
	newdata[4] = srcprtbytes[0]
	newdata[5] = srcprtbytes[1]
	// copy data to newdata
	for index, element := range data {
		newdata[index+6] = element
	}
	// write the data
	_, err = Conn.Write(newdata)
	if err != nil {
		log.Error("Error sending UDP", err)
		return err
	}
	// return nil on success
	return nil
}

// helper to turn a uint into it's lower 2 bytes
func uintToBytes(input uint) []byte {
	// this must be less than 1024 so we only have a few use cases
	output := make([]byte, 2)
	lower := input & 0xFF
	output[1] = byte(lower)
	upper := (input >> 8) & 0xFF
	output[0] = byte(upper)
	return output
}
