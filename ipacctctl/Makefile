#
# $Id: Makefile,v 1.9 2005/07/31 07:57:41 romanp Exp $
#

BINDIR?=	/usr/local/sbin

PROG=		ipacctctl
.if !exists(/usr/share/mk/bsd.compat.mk)
# Pre NOFOO -> NO_FOO system
NOMAN=		YES
.else
NO_MAN=		YES
.endif

COPTS+=		-g -Wall -Wformat
LDADD+=		-lnetgraph

.include <bsd.prog.mk>
