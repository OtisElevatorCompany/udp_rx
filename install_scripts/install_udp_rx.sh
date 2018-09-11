# create a service user
echo "Creating User"
useradd -r udprx
# create /etc/udp_rx directory
echo "Creating udp_rx directories"
mkdir -p /etc/udp_rx
chmod 755 /etc/udp_rx
# move the default portlist to that directory
echo "Moving portslist and setting permissions"
cp portslist /etc/udp_rx/
chown root /etc/udp_rx/portslist
chgrp root /etc/udp_rx/portslist
chmod 644 /etc/udp_rx/portslist
# move the default config file to that directory
echo "Moving configuration files"
cp udp_rx_conf.json /etc/udp_rx/
chown root /etc/udp_rx/udp_rx_conf.json
chgrp root /etc/udp_rx/udp_rx_conf.json
chmod 644 /etc/udp_rx/udp_rx_conf.json
# move udp_rx and set_firewall to /usr/sbin
echo "moving executables and setting permissions"
cp udp_rx /usr/sbin/
cp udprx_firewall /usr/sbin
chown root /usr/sbin/udp_rx
chgrp root /usr/sbin/udp_rx
chown root /usr/sbin/udprx_firewall
chgrp root /usr/sbin/udprx_firewall
chmod 4755 /usr/sbin/udp_rx
chmod 4755 /usr/sbin/udprx_firewall
# move unit file to /lib/systemd/system
echo "Installing the service"
cp udp_rx.service /lib/systemd/system
chmod 644 /lib/systemd/system/udp_rx.service
systemctl daemon-reload
echo "udp_rx service is installed."
echo "place keys into /etc/udp_rx or change the default configuration found in /etc/udp_rx/udp_rx_conf.json"
echo "Run systemctl start udp_rx.service after the keys are installed"
#systemctl start name.service