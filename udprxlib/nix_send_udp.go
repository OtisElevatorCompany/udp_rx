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
	"bytes"
	"encoding/binary"
	"errors"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//fd is the int representing a linux file descriptor for a raw socket. Init to -1 to represent an uninit file descriptor
var fd = -1

//CreateUDPSocket creates a UDP socket and returns the filedescriptor (int) or an error
func CreateUDPSocket() error {
	log.Info("Creating linux raw udp socket...")
	tfd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil || tfd < 0 {
		log.Fatal("Couldn't create socket", err)
		return err
	}
	log.Info("socket created, creating soccket int")
	err = unix.SetsockoptInt(tfd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal("couldn't get socket int", err)
		unix.Close(fd)
		return err
	}
	log.Info("socket created and set")
	//set fd after success and return no-error
	fd = tfd
	return nil
}

//SendUDP takes in the associated data and puts a UDP packet on the wire
func SendUDP(srcipstr string, destipstr string, srcprt uint, destprt uint, data []byte, counter int) error {
	//parse the ips
	srcip, destip, err := ParseIps(srcipstr, destipstr)
	if err != nil {
		log.Error("error in parse ips")
		return err
	}
	//create an IP packet header
	ip := Iphdr{
		vhl:   0x45,
		tos:   0,
		id:    0x1234, // the kernel overwrites id if it is zero
		off:   0,
		ttl:   64,
		proto: unix.IPPROTO_UDP,
	}
	//copy the ip addresses to the IP header
	copy(ip.src[:], srcip.To4())
	copy(ip.dst[:], destip.To4())
	//create a UDP header
	udp := Udphdr{
		src: uint16(srcprt),
		dst: uint16(destprt),
	}
	// just use an empty IPv4 sockaddr for Sendto
	// the kernel will route the packet based on the IP header
	addr := unix.SockaddrInet4{}
	udplen := 8 + len(data)
	totalLen := 20 + udplen
	if totalLen > 0xffff {
		return errors.New("Message too large to fit into a packet")
	}
	//run Checksums
	//ip
	ip.iplen = uint16(totalLen)
	ip.Checksum()
	//udp
	udp.ulen = uint16(udplen)
	udp.Checksum(&ip, data)
	//write the packet
	var b bytes.Buffer
	err = binary.Write(&b, binary.BigEndian, &ip)
	if err != nil {
		log.Error("Error encoding ip header")
		return err
	}
	err = binary.Write(&b, binary.BigEndian, &udp)
	if err != nil {
		log.Error("Error encoding udp header")
		return err
	}
	err = binary.Write(&b, binary.BigEndian, &data)
	if err != nil {
		log.Error("Error encoding data section")
		return err
	}
	bb := b.Bytes()
	err = unix.Sendto(fd, bb, 0, &addr)
	if err != nil {
		log.WithFields(log.Fields{
			"fd":   fd,
			"bb":   bb,
			"addr": addr,
		}).Error("Error in unix.Sendto")
		return err
		//return errors.New("Error sending packet")
	}
	//return nil on success
	return nil
}
