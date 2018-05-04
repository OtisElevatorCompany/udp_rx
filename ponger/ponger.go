package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	/* Lets prepare a address at any address at port 10001*/
	ServerAddr, err := net.ResolveUDPAddr("udp", ":4444")
	if err != nil {
		log.Fatal("Couldn't resolve localhost at port")
	}
	UdprAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:55555")
	if err != nil {
		log.Fatal("Couldn't resolve udpr at port")
	}
	Conn, err := net.DialUDP("udp", nil, UdprAddr)
	if err != nil {
		panic("couldn't dial udpr")
	}
	defer Conn.Close()

	/* Now listen at selected port */
	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	if err != nil {
		log.Fatal("Couldn't listen UDP")
	}
	defer ServerConn.Close()

	buf := make([]byte, 1024)
	counter := 0
	for {
		n, addr, err := ServerConn.ReadFromUDP(buf)
		fmt.Printf("ponger - Got packet, %d\n", counter)
		tosend := make([]byte, n+4+2+8)
		tosend[0] = addr.IP.To4()[0]
		tosend[1] = addr.IP.To4()[1]
		tosend[2] = addr.IP.To4()[2]
		tosend[3] = addr.IP.To4()[3]
		//port 4445
		tosend[4] = 0x11
		tosend[5] = 0x5D
		//move data over to tosend
		for i, b := range buf {
			if i == n {
				break
			}
			//fmt.Printf("data: %d\n", b)
			tosend[6+i] = b
		}
		//set time at end of tosend
		for index, element := range getTimeBytes() {
			tosend[6+n+index] = element
			//fmt.Printf("ponger - %d\n", element)
		}
		// for _, element := range tosend {
		// 	fmt.Printf("tosend: %d\n", element)
		// }
		//send it
		Conn.Write(tosend)
		//fmt.Printf("ponger - echoed, %d, %s\n", counter, strconv.FormatInt(time.Now().UTC().UnixNano(), 10))
		counter++
		if err != nil {
			fmt.Println("Error: ", err)
		}

	}
}

func getTimeBytes() []byte {
	barray := make([]byte, 8)
	time := time.Now().UTC().UnixNano()
	barray[0] = byte((time >> 56) & 0xFF)
	barray[1] = byte((time >> 48) & 0xFF)
	barray[2] = byte((time >> 40) & 0xFF)
	barray[3] = byte((time >> 32) & 0xFF)
	barray[4] = byte((time >> 24) & 0xFF)
	barray[5] = byte((time >> 16) & 0xFF)
	barray[6] = byte((time >> 8) & 0xFF)
	barray[7] = byte(time & 0xFF)
	return barray
}
