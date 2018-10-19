# Windows Installation
## Steps using prebuilt binaries (releases)
* Run `udp_rx_installer.exe`
* Select your service startup type (default is `manual`)
* Select your secrets (use `udp_rx_cert_creator.exe` if building your own dev keys)
* ensure that port `tcp:55554` is open in the device firewall
    * Note: this port can be changed if needed, but 55554 is the default
* Start the udp_rx service

## Building windows binaries
* Clone this repository in its entirety
* ensure that you have visual studio 2015+ and Go 1.9+ (1.11 recomended)
* open `udprx_win_service\udp_rx_installer\udp_rx_installer.sln` in visual studio 2015+
* Build the solution. This will automatically build `udprx_win_service` and `udp_rx_cert_creator` and an installer file
* Perform the steps listed in the using prebuilt binaries section