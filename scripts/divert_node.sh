#!/bin/sh

### Dmitry Frolov <frolov@riss-telecom.ru>
### $Id: divert_node.sh,v 1.5 2002/07/31 07:53:43 romanp Exp $

IFACE="xl0"
THRESHOLD=1000
VERBOSE="1"

### to manipulate a node use "ipacctctl ipacct_${IFACE}:$IFACE} <command...>".

nodename=ipacct_${IFACE}
hookprefix=${IFACE}

case "$1" in
	stop)

		ipfw del 64021 64022

		ngctl shutdown ${nodename}:

		;;

	show)
		ipacctctl ${nodename}:${hookprefix} checkpoint
		ipacctctl ${nodename}:${hookprefix} show
		ipacctctl ${nodename}:${hookprefix} clear
		;;

	start|*)

		### we must create two hooks, ${hookprefix}_in and
		### ${hookprefix}_out to simulate input and output
		### streams
		ngctl -f- <<-SEQ
			### dummy hook, to create a node
			mkpeer ipacct ctl ctl 
			name .:ctl ${nodename}
			### "incoming" hook 
			mkpeer ${nodename}: ksocket ${hookprefix}_in inet/raw/divert
			name ${nodename}:${hookprefix}_in ${nodename}_in     
			msg ${nodename}_in: bind inet/0.0.0.0:3021
			### "outgoing" hook
			mkpeer ${nodename}: ksocket ${hookprefix}_out inet/raw/divert
			name ${nodename}:${hookprefix}_out ${nodename}_out
			msg ${nodename}_out: bind inet/0.0.0.0:3022
			rmhook .:ctl
		SEQ
		ipacctctl ${nodename}:${hookprefix} dlt RAW
		ipacctctl ${nodename}:${hookprefix} v  ${VERBOSE}
		ipacctctl ${nodename}:${hookprefix} th  ${THRESHOLD}
		
		### packets reaching tee are _accepted_, 
		### so use theese rules _AFTER_ all deny rules
		ipfw add 64021 tee 3021 ip from any to room101 via ${IFACE}
		ipfw add 64022 tee 3022 ip from room101 to any via ${IFACE}

		;;
esac
