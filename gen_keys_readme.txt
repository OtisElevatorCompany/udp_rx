To generate a testing Certificate Authority, run the "build_testing_ca.sh" script in the keys directory. 
This creates a self signed CA with a 4096 bit key (recomended).

To build a new device key run the 'udp_rx_cert_creator' tool giving it the correct input and output paths.
(run ./udp_rx_cert_creator -h to see the accepted arguments)
