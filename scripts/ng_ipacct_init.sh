#!/bin/sh
# ng_ipacct traffic counter
#
# Contributed by Alexei Zakirov
#
# $Id: ng_ipacct_init.sh,v 1.6 2001/10/25 15:08:31 romanp Exp $
#

THRESHOLD=50000
VERBOSE=1
IPACCTCTL="/usr/local/sbin/ipacctctl"
INTERFACES="ed0"

case "$1" in
    start)
	# XXX should check via kldstat is module already loaded
	kldload netgraph > /dev/null 2>&1
	kldload ng_ether > /dev/null 2>&1
	kldload ng_socket > /dev/null 2>&1
	kldload ng_tee > /dev/null 2>&1
	kldload ng_ipacct > /dev/null 2>&1

	for IFACE in $INTERFACES; do
		ngctl mkpeer ${IFACE}: tee lower right
		ngctl connect ${IFACE}: lower upper left
		ngctl name ${IFACE}:lower ${IFACE}_acct_tee
		ngctl mkpeer ${IFACE}_acct_tee: ipacct right2left ${IFACE}_in
		ngctl name ${IFACE}_acct_tee:right2left ${IFACE}_ip_acct
		ngctl connect ${IFACE}_acct_tee: ${IFACE}_ip_acct: left2right ${IFACE}_out
		$IPACCTCTL ${IFACE}_ip_acct:$IFACE verbose $VERBOSE
		$IPACCTCTL ${IFACE}_ip_acct:$IFACE threshold $THRESHOLD
	done
	;;

    stop)
	for IFACE in $INTERFACES; do
		ngctl shutdown ${IFACE}_acct_tee:
		ngctl shutdown ${IFACE}:
	done
	kldunload ng_ipacct
	;;

    *)
	echo ""
	echo "Usage: `basename $0` { start | stop }"
	echo ""
	;;
esac
