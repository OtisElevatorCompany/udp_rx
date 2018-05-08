package main

import (
	"errors"
	"net"
)

//declare a type for the forwardPacketFn
type sendUDPFn func(srcipstr string, destipstr string, srcprt uint, destprt uint, data []byte, counter int) error

//Iphdr is the IP header struct
type Iphdr struct {
	vhl   uint8
	tos   uint8
	iplen uint16
	id    uint16
	off   uint16
	ttl   uint8
	proto uint8
	csum  uint16
	src   [4]byte
	dst   [4]byte
}

//Udphdr is the UDP header struct
type Udphdr struct {
	src  uint16
	dst  uint16
	ulen uint16
	csum uint16
}

// pseudo header used for checksum calculation
type pseudohdr struct {
	ipsrc   [4]byte
	ipdst   [4]byte
	zero    uint8
	ipproto uint8
	plen    uint16
}

//the actual IP checksum function
func checksum(buf []byte) uint16 {
	sum := uint32(0)

	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	/*
	 * From RFC 768:
	 * If the computed checksum is zero, it is transmitted as all ones (the
	 * equivalent in one's complement arithmetic). An all zero transmitted
	 * checksum value means that the transmitter generated no checksum (for
	 * debugging or for higher level protocols that don't care).
	 */
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

//Checksum - sets checksum for an IP header
func (h *Iphdr) Checksum() {
	h.csum = 0
	// var b bytes.Buffer
	// binary.Write(&b, binary.BigEndian, h)
	// h.csum = checksum(b.Bytes())
}

//Checksum - sets checksum for an UDP header
func (u *Udphdr) Checksum(ip *Iphdr, payload []byte) {
	u.csum = 0
	// phdr := pseudohdr{
	// 	ipsrc:   ip.src,
	// 	ipdst:   ip.dst,
	// 	zero:    0,
	// 	ipproto: ip.proto,
	// 	plen:    u.ulen,
	// }
	// var b bytes.Buffer
	// binary.Write(&b, binary.BigEndian, &phdr)
	// binary.Write(&b, binary.BigEndian, u)
	// binary.Write(&b, binary.BigEndian, &payload)
	// u.csum = checksum(b.Bytes())
}

//ParseIps parses ip address string and returns them as net objects
func ParseIps(srcipstr string, destipstr string) (net.IP, net.IP, error) {
	srcip := net.ParseIP(srcipstr)
	if srcip == nil {
		return nil, nil, errors.New("Couldn't parse source IP")
	}
	destip := net.ParseIP(destipstr)
	if destip == nil {
		return nil, nil, errors.New("Couldn't parse destination IP")
	}
	return srcip, destip, nil
}
