#
# $Id: Makefile,v 1.9 2005/07/31 07:57:41 romanp Exp $
#

BINDIR?=	/usr/local/sbin

PROG=		ipacctctl

.if defined(OSVERSION)
.if ${OSVERSION} > 1100100
MK_MAN=			no
.else
NO_MAN=
.endif
.else
MK_MAN=			no
.endif

CFLAGS+=	-g -Wall -Wformat
LDADD+=		-lnetgraph

.include <bsd.prog.mk>
