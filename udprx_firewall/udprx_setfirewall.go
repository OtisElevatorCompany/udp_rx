package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	portsList := flag.String("portlist", "/etc/udp_rx/portslist", "Override the default ports list")
	unsetFlag := flag.Bool("-unset", false, "if set to true, will unset the iptables rules")
	flag.Parse()

	// get a list of this machines interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Couldn't get interfaces. Error: %s", err.Error())
	}

	// foreach line in the portslist
	file, err := os.Open(*portsList)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// deny to each interface
		portNumber := scanner.Text()
		// attempt to parse to an int, if it fails, don't try to run iptables command
		_, err := strconv.Atoi(portNumber)
		if err != nil {
			log.Printf("bypassing line, invalid format: %s\n", portNumber)
			continue
		}
		//try to parse to an int, continue if we can't
		for _, netInterface := range interfaces {
			if strings.HasPrefix(netInterface.Name, "lo") {
				// iptables -I input -i eth0 -p udp --dport [port to REJECT] -j REJECT
				var setArg string
				if !*unsetFlag {
					setArg = "-I"
				} else {
					setArg = "-D"
				}
				cmd := exec.Command("iptables", setArg, "INPUT", "-i", netInterface.Name, "-p", "udp", "--dport", portNumber, "-j", "REJECT")
				if err := cmd.Run(); err != nil {
					if !*unsetFlag {
						log.Printf("Error creating firewall rules. Error: %s", err.Error())
					} else {
						log.Printf("Error deleting firewall rules. Error: %s", err.Error())
					}
				}

			}

		}
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
