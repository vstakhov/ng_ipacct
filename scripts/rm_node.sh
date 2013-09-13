#! /bin/sh 
#
# $Id: rm_node.sh,v 1.4 2004/11/27 17:43:59 romanp Exp $
#

IFACE=$1

ngctl shutdown ${IFACE}_acct_tee:
ngctl shutdown ${IFACE}:
kldunload ng_ipacct
