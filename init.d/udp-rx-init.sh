#! /bin/sh

startdaemon(){

	echo "Start UDP RX..."
	if [ -f /usr/sbin/udp_rx ]
	then
		/usr/sbin/udp_rx >> /dev/null 2>&1 &
	fi
}

stopdaemon(){
	echo "Stopping UDP RX..."
	pkill -ef "udp_rx"
}

case "$1" in
	start)
		startdaemon
		;;
	stop)
		stopdaemon
		;;
	restart)
		stopdaemon
		startdaemon
		;;
	*)
		echo "Usage: udp-rx-init.sh { start | stop | restart }" >&2
		exit 1
		;;
esac

exit 0

