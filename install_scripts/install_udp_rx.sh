# create a service user
useradd -r udprx
# create /etc/udp_rx directory
mkdir -p /etc/udp_rx
chmod 755 /etc/udp_rx
# move the default portlist to that directory
cp portslist /etc/udp_rx/
chown root /etc/udp_rx/portslist
chgrp root /etc/udp_rx/portslist
chmod 644 /etc/udp_rx/portslist
# move the default config file to that directory
cp udp_rx_conf.json /etc/udp_rx/
chown root /etc/udp_rx/udp_rx_conf.json
chgrp root /etc/udp_rx/udp_rx_conf.json
chmod 644 /etc/udp_rx/udp_rx_conf.json
# move udp_rx and set_firewall to /usr/sbin
cp udp_rx /usr/sbin/
cp udprx_firewall /usr/sbin
chown root /usr/sbin/udp_rx
chgrp root /usr/sbin/udp_rx
chown root /usr/sbin/udprx_firewall
chgrp root /usr/sbin/udprx_firewall
chmod 4755 /usr/sbin/udp_rx
chmod 4755 /usr/sbin/udprx_firewall
# move unit file to /lib/systemd/system
cp udp_rx.service /lib/systemd/system
chmod 644 /lib/systemd/system/udp_rx.service
systemctl daemon-reload
#systemctl start udp_rx.service
