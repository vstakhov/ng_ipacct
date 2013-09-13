#! /bin/sh 
#
# $Id: add_node.sh,v 1.10 2004/11/27 17:43:59 romanp Exp $
#

IFACE=$1

# XXX should check via kldstat is module already loaded
kldload netgraph > /dev/null 2>&1
kldload ng_ether > /dev/null 2>&1
kldload ng_socket > /dev/null 2>&1
kldload ng_tee > /dev/null 2>&1
kldload ng_ipacct > /dev/null 2>&1


ngctl mkpeer ${IFACE}: tee lower right
ngctl connect ${IFACE}: lower upper left
ngctl name ${IFACE}:lower ${IFACE}_acct_tee
ngctl mkpeer ${IFACE}_acct_tee: ipacct right2left ${IFACE}_in
ngctl name ${IFACE}_acct_tee:right2left ${IFACE}_ip_acct
ngctl connect ${IFACE}_acct_tee: ${IFACE}_ip_acct: left2right ${IFACE}_out

ipacctctl ${IFACE}_ip_acct:${IFACE} th 10000
ipacctctl ${IFACE}_ip_acct:${IFACE} v 1
ipacctctl ${IFACE}_ip_acct:${IFACE} savetime 1

