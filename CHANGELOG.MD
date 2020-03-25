# udp_rx Changelog
## AAA
This is a 1.0 release. 

* added flag for log file location: `logpath`
* default log path on Linux is now: `/var/log/udp_rx`
* Default log path on Windows is now: `c:\programdata\udp_rx\udp_rx.log`

## A25
**This is still pre-1.0**
Fixed a bug where duplicate IPTables rules could be created by `udprx_firewall` and would not be deleted by `udprx_firewall -unset` 