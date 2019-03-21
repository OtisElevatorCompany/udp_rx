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
	unsetFlag := flag.Bool("unset", false, "if set to true, will unset the iptables rules")
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
		// try to parse to an int, continue if we can't
		for _, netInterface := range interfaces {
			if !strings.HasPrefix(netInterface.Name, "lo") {
				// iptables -[IDC] INPUT -i eth0 -p udp --dport [port to REJECT] -j REJECT
				if !*unsetFlag {
					//if there was NO error, the rule already exists, continue
					if runIPTables("-C", portNumber, netInterface.Name) == nil {
						continue
					}
					//otherwise add it
					err = runIPTables("-I", portNumber, netInterface.Name)
					if err != nil {
						log.Printf("Error creating firewall rule. Error: %s", err.Error())
						continue
					}
				} else {
					for {
						if runIPTables("-D", portNumber, netInterface.Name) != nil {
							break
						}
					}
				}

			}

		}
		fmt.Println(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	if *unsetFlag {
		log.Print("udprx_firewall - Unset firewall")
	} else {
		log.Print("udprx_firewall - set firewall")
	}

}

func runIPTables(setArg, portNumber, netInterface string) error {
	cmd := exec.Command("iptables", setArg, "INPUT", "-i", netInterface, "-p", "udp", "--dport", portNumber, "-j", "REJECT")
	return cmd.Run()
}
