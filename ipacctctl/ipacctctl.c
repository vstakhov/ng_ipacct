/*-
 * Copyright (c) 2001-2005 Roman V. Palagin <romanp@unshadow.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	 $Id: ipacctctl.c,v 1.38 2006/12/23 09:56:22 romanp Exp $
 */

#ifndef lint
static const char rcs_id[] = 
    "@(#) $Id: ipacctctl.c,v 1.38 2006/12/23 09:56:22 romanp Exp $";
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <inttypes.h>

#include <net/bpf.h>        /* for DLT_XXX consts */
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netgraph.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "../ng_ipacct/ng_ipacct.h"

#define	TIME_FMT	"%Y/%m/%d %H:%M:%S" 	/* used in strftime() */
#define	IN_HOOK		0
#define OUT_HOOK	1

#ifndef PRIu64
#define PRIu64	"qu"
#endif

int main(int, char **);

static int ip_account_get_info(int _type, void *_buf, int _len, int _out);
static int ip_account_show(int _verbose, int _out);
static int ip_account_set(int _var, int _len, void *_data);
static int ip_account_ctl(int _code, int _out);
static int ip_account_print(struct ip_acct_chunk *recs, int flags);
static int ip_account_read(char *_fname, char *_rflags);

static int ip_ctl_ctl(int, int, char **);
static int ip_ctl_set(int, int, char **);
static int ip_ctl_set_flag(int, int, char **);
static int ip_ctl_stat(int, int, char **);
static int ip_ctl_show(int, int, char **);
static int ip_ctl_dlt(int, int, char **);

static void help(void);
static void execute_command(int, char **);
static void print_info(int _type, void *_buf, int _out);
static struct ng_ipacct_vinfo *check_version(void);
static int  ng_ready_for_read(void);
   
struct ip_ctl_cmd {
	char	*cmd_name;
	int	cmd_code;
	int	(*cmd_func)(int code, int argc, char **argv);
};

struct ip_ctl_cmd cmds[] = {
    {"checkpoint",	NGM_IPACCT_CHECK, 	ip_ctl_ctl}, 
    {"clear",		NGM_IPACCT_CLEAR, 	ip_ctl_ctl},
    {"debug",		NGM_IPACCT_DLEVEL, 	ip_ctl_set},
    {"show",		NGM_IPACCT_SHOW,	ip_ctl_show},
    {"stat",		NGM_IPACCT_HINFO,	ip_ctl_stat},
    {"threshold",	NGM_IPACCT_STHRS,	ip_ctl_set},
    {"saveuid",		HI_SAVE_UID,		ip_ctl_set_flag},
    {"verbose",		HI_VERBOSE_MODE,	ip_ctl_set_flag},
    {"savetime",	HI_SAVE_TIME,		ip_ctl_set_flag},
    {"dlt",			NGM_IPACCT_SETDLT,	ip_ctl_dlt},
    {NULL,			0,					NULL},
};

struct dlts {
    char    *dlt_name;
    int     dlt_type;
} dlts[] = {
        { "RAW", DLT_RAW },
        { "EN10MB", DLT_EN10MB },
        { "NGGIF", INT_DLT_NGGIF },
        { NULL, 0 },
};

static __inline int dlt_name2type(char *name)
{
    int i, dlt = -1;

	for (i = 0; dlts[i].dlt_name != NULL; i++) {
		if (strcasecmp(name, dlts[i].dlt_name) == 0) {
			dlt = dlts[i].dlt_type;
			break;
		}
	}

    return (dlt);
}

static __inline char *dlt_type2name(int type)
{
    int i;
    char *name = NULL;

	for (i = 0; dlts[i].dlt_name != NULL; i++) {
		if (type == dlts[i].dlt_type) {
            name = dlts[i].dlt_name;
			break;
		}
	}

    return (name);
}

int	    ng_cs;
char	ng_nodename[NG_PATHLEN + 1], *ng_hookprefix;
int	    fl_use_in, fl_use_out, fl_rfile, fl_ipnum;
FILE	*wfp;
struct	ng_ipacct_vinfo	*g_vinfo;
int     read_to = 1;

int
main(int argc, char **argv)
{
	int     c;
	char    sname[16];
    char	*ng_name;
	char	*rflags = "0", *rfname = NULL, *wfname = NULL;

	fl_use_in = fl_use_out = 1;

	/* parse options */
	while ((c = getopt(argc, argv, "T:d:f:inor:w:")) != -1) {
		switch (c) {
        case 'T':   /* set socket ready timeout, in secs. */
            read_to = atoi(optarg);
            break;

		case 'd':	/* set libnetgraph debug level. */
			NgSetDebug(atoi(optarg));
			break;

		case 'f':	/* flags for -r switch */
			rflags = optarg;
			break;

		case 'i':	/* use only input hook */
			fl_use_in = 1;
			fl_use_out = 0;
			break;
		case 'n':
			fl_ipnum = 1;
			break;
		case 'o':	/* use only output hook */
			fl_use_out = 1;
			fl_use_in = 0;
			break;

		case 'r':	/* get data from file, not from node */
			fl_rfile = 1;
			rfname = optarg;
			break;

		case 'w':	/* write data in binary to file */
			wfname = optarg;
			break;
			
		}
	}

	if (fl_rfile) {
		ip_account_read(rfname, rflags);
		exit(0);
	}

	if (wfname != NULL) {
		wfp = fopen(wfname, "a");
		if (wfp == NULL)
			err(1, "fopen");
	}

	argc -= optind;
	argv += optind;
	ng_name = argv[0];
	if (ng_name == NULL)
		help();
	argc --;
	argv ++;

	if((ng_hookprefix = strchr(ng_name, ':')))
		*(ng_hookprefix++) = '\0';
	else
		ng_hookprefix = ng_nodename;
	snprintf(ng_nodename, sizeof(ng_nodename), "%s:", ng_name);

	/* creat control socket. */
	snprintf(sname, sizeof(sname), "ipacct%i", getpid());

	if (NgMkSockNode(sname, &ng_cs, NULL) == -1)
		err(1, "NgMkSockNode");
#if 0
	/* set control socket nonblocking */
	if ((flags = fcntl(ng_cs, F_GETFL, 0)) == -1)
		err(1, "fcntl(F_GETFL)");
	flags |= O_NONBLOCK;
	if (fcntl(ng_cs, F_SETFL, flags) == -1)
		err(1, "fcntl(F_SETFL)");

    /* 
     * XXX we don't set receive buffer size 'cause
     * reply size (NG control message + accounting
     * chunk) is smaller than default buffer size.
     * But this is sometimes can be not true.
     */

	/* set receive buffer size */
	if (setsockopt(ng_cs, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(int)) == -1)
		err(1, "setsockopt(SOL_SOCKET, SO_RCVBUF)");
#endif
	/* check versions */
	g_vinfo = check_version();

	/* parse and execute command */
	execute_command(argc, argv);

	close(ng_cs);
	
	exit(0);
}

static void
execute_command(int argc, char **argv)
{
	int cindex = -1, i;

	if (!argc) {
		help();
		return;
	}
	for (i = 0; cmds[i].cmd_name != NULL; i++)
		if (!strncmp(argv[0], cmds[i].cmd_name, strlen(argv[0]))) {
			if (cindex != -1) {
				warnx("ambiguous command: %s", argv[0]);
				return;
			}
			cindex = i;
		}
	if (cindex == -1) {
		warnx("bad command: %s", argv[0]);
		return;
	}
	argc --;
	argv ++;
	(*cmds[cindex].cmd_func)(cmds[cindex].cmd_code, argc, argv);
	return;
}

static struct ng_ipacct_vinfo *
check_version(void)
{
	int 	error, blen;
	void	*buf;
	struct 	ng_ipacct_vinfo *vinfo;

	vinfo = buf = malloc((blen = sizeof(struct ng_ipacct_vinfo)));
	error = ip_account_get_info(NGM_IPACCT_VINFO, buf, blen, IN_HOOK);
	if (error) {
		errx(1, "Cann't get version number from node");
	}
	if (vinfo->vi_api_version != NGM_IPACCT_APIVER) {
		errx(1, "API version mismatch: got %d, expect %d", 
		    vinfo->vi_api_version, NGM_IPACCT_APIVER);
	}

	return vinfo;
}

static int
ip_ctl_ctl(int code, int argc, char **argv)
{
	if (fl_use_in)
		ip_account_ctl(code, IN_HOOK);
	if (fl_use_out)
		ip_account_ctl(code, OUT_HOOK);

	return (0);
}

static int
ip_ctl_set(int code, int argc, char **argv)
{
	int	value;

	if (argc == 0) {
		warnx("ip_ctl_set: missing argument");
		return (-1);
	}
	
	value = strtol(argv[0], (char **)NULL, 0);
	ip_account_set(code, sizeof(value), &value);

	return (0);
}

static int
ip_ctl_set_flag(int flag, int argc, char **argv)
{
	int	code;
	
	if (argc == 0) {
		warnx("ip_ctl_set_flag: missing argument");
		return (-1);
	}
	code = (atoi(argv[0])) ? NGM_IPACCT_SFLAGS : NGM_IPACCT_CFLAGS;
	ip_account_set(code, sizeof(flag), &flag);
	return (0);
}

static int
ip_ctl_show(int code, int argc, char **argv)
{
	int v;

	v = ((argc == 1) && (argv[0][0] = 'v'));

	if (fl_use_in)
		ip_account_show(v, IN_HOOK);
	if (fl_use_out)
		ip_account_show(v, OUT_HOOK);

	return (0);
}

static int
ip_ctl_dlt(int code, int argc, char **argv)
{
	int	dlt;

	if (argc == 0) {
		warnx("ip_ctl_dlt: missing argument");
		return (-1);
	}

    dlt = dlt_name2type(argv[0]);

	if (dlt == -1) {
		warnx("ip_ctl_dlt: unknow DLT type: %s", argv[0]);
		return (-1);
	}

	ip_account_set(code, sizeof(dlt), &dlt);

	return (0);
}


static int
ip_ctl_stat(int code, int argc, char **argv)
{
	int			type, blen;
	struct ng_ipacct_hinfo	hinfo;
	struct ng_ipacct_ainfo	ainfo;
	void 			*buf;

	if (argc == 0) {
		warnx("stat: missing arg");
		return (-1);
	}
	
	switch (argv[0][0]) {
	case 'v':
		printf("Version: %s\n", rcs_id);
		printf("Kernel module version: %s\n", g_vinfo->vi_kernel_id);
		printf("NG_ipacct API version: %d\n", g_vinfo->vi_api_version);
		return (0);
	case 'h':
		buf = &hinfo;
		blen = sizeof(hinfo);
		type = NGM_IPACCT_HINFO;
		break;
	case 'a':
		buf = &ainfo;
		blen = sizeof(ainfo);
		type = NGM_IPACCT_AINFO;
		break;
	case 'c':
		buf = &ainfo;
		blen = sizeof(ainfo);
		type = NGM_IPACCT_CINFO;
		break;
	default:
		warnx("stat: unknow stat type: %s", argv[0]);
		return(-1);
	}
	
	if (fl_use_in)
		if (!ip_account_get_info(type, buf, blen, IN_HOOK))
			print_info(type, buf, IN_HOOK);
	if (fl_use_out)
		if (!ip_account_get_info(type, buf, blen, OUT_HOOK))
			print_info(type, buf, OUT_HOOK);
	return (0);
}

static void
print_info(int type, void *buf, int outgoing)
{
	if (type == NGM_IPACCT_HINFO) {
		struct ng_ipacct_hinfo *hi = (struct ng_ipacct_hinfo*)buf;
		char stime[128];

		printf("hook name:\t\t\t%s_%s\n", 
		    ng_hookprefix, (outgoing) ? "out" : "in");
		printf("expected traffic type:\t\t%s\n", 
		    (hi->hi_flags & HI_INCOMING_HOOK) ? 
		    "incoming" : "outgoing");
		printf("debug level:\t\t\t0x%08x\n",
		    hi->hi_debug);
		printf("flags:\n");
		if (hi->hi_flags & HI_VERBOSE_MODE)
			printf("\t- verbose mode\n");
		if (hi->hi_flags & HI_SAVE_UID)
			printf("\t- save uids\n");
		if (hi->hi_flags & HI_SAVE_TIME)
			printf("\t- save time\n");
		printf("data-link type:\t\t\t%d (%s)\n", 
		    hi->hi_dlt, dlt_type2name(hi->hi_dlt));
		printf("number of hash records:\t\t%u\n", 
		    hi->hi_records);
		printf("hash records threshold:\t\t%u\n", 
		    hi->hi_threshold);
		strftime(stime, sizeof(stime), TIME_FMT, localtime(&hi->hi_thrs_when));
		printf("threshold was exceeded:\t\t%s\n", 
		    (hi->hi_thrs_when) ? stime : "Never");
		printf("total number of packets:\t%u\n", 
		    hi->hi_packets);
		printf("total number of bytes:\t\t%" PRIu64 "\n", 
		    hi->hi_bytes);
		return;
	}

	if ((type == NGM_IPACCT_CINFO) ||
	    (type == NGM_IPACCT_AINFO)) {
		struct ng_ipacct_ainfo *ai = (struct ng_ipacct_ainfo*)buf;
		char stime[128];
		
		printf("hook name:\t\t%s_%s\n", 
		    ng_hookprefix, (outgoing) ? "out" : "in");
		printf("database type:\t\t%s\n",
		    (type == NGM_IPACCT_CINFO) ? "checkpointed" : "active");
		printf("accounted:\t\tpackets: %u\tbytes: %" PRIu64 "\n", 
		    ai->ai_packets, ai->ai_bytes);
		printf("exceed threshold:\tpackets: %u\tbytes: %" PRIu64 "\n",
		    ai->ai_th_packets, ai->ai_th_bytes);
		strftime(stime, sizeof(stime), TIME_FMT, localtime(&ai->ai_start));
		printf("database was created:\t%s\n", 
		    (ai->ai_start) ? stime : "Never");
		strftime(stime, sizeof(stime), TIME_FMT, localtime(&ai->ai_last));
		printf("database last updated:\t%s\n", 
		    (ai->ai_last) ? stime : "Never");
		return;
	}
	warnx("unknow info type: %d", type);
	return;
}

/*
 * Retrieve hook or database info
 */
static int
ip_account_get_info(int type, void *buf, int blen, int outgoing)
{
	int token, error;
	struct ng_mesg *ng_mesg;
	char path[NG_PATHLEN + 1];

	/* send control message */
	if ((token = ip_account_ctl(type, outgoing)) == -1)
		return (-1);

	/* read reply */
    if (ng_ready_for_read() != 1)
        return (-1);
	ng_mesg = alloca(sizeof(*ng_mesg) + blen);
	error = NgRecvMsg(ng_cs, ng_mesg, (sizeof(*ng_mesg) + blen), path);

	if (error == -1) {
		warn("NgRecvMsg(NGM_IPACCT_xINFO)");
		return (-1);
	}
	if (ng_mesg->header.token != token) {
		warnx("NgRecvMsg(NGM_IPACCT_xINFO): token mismatch");
		return (-1);
	}
	if (ng_mesg->header.arglen < blen) {
		warnx("NgRecvMsg(NGM_IPACCT_xINFO): arglen too small, "
		      "arglen = %d, blen = %d", 
		    ng_mesg->header.arglen, blen);
		return (-1);
	}

	bcopy(ng_mesg->data, buf, blen);

	return (0);
}

/*
 * Send control message to ng_ipacct node
 */
static int
ip_account_ctl(int code, int outgoing)
{
	int token;
	struct ng_ipacct_mesg ng_cmesg;

	snprintf(ng_cmesg.hname, sizeof(ng_cmesg.hname),
	    "%s_%s", ng_hookprefix, outgoing ? "out" : "in");

	/* send message */
	token = NgSendMsg(ng_cs, ng_nodename, NGM_IPACCT_COOKIE, 
		    code, &ng_cmesg, sizeof(ng_cmesg));
	if (token == -1) {
		warn("ip_account_ctl: NgSendMsg");
	}

	return (token);
}

static int
ip_account_set(int var, int len, void *data)
{
	int token_in = 0, token_out = 0;
	struct ng_ipacct_mesg *ng_cmesg;
	
	if (fl_use_in) {
		ng_cmesg = alloca(sizeof(*ng_cmesg) + len);
		snprintf(ng_cmesg->hname, sizeof(ng_cmesg->hname), "%s_in", ng_hookprefix);
		bcopy(data, ng_cmesg->data, len);
		/* send message */
		token_in = NgSendMsg(ng_cs, ng_nodename, NGM_IPACCT_COOKIE, 
		    var, ng_cmesg, sizeof(*ng_cmesg) + len);
		if (token_in == -1) {
			warn("ip_account_set: NgSendMsg");
		}
	}

	if (fl_use_out) {
		ng_cmesg = alloca(sizeof(*ng_cmesg) + len);
		snprintf(ng_cmesg->hname, sizeof(ng_cmesg->hname), "%s_out", ng_hookprefix);
		bcopy(data, ng_cmesg->data, len);
		/* send message */
		token_out = NgSendMsg(ng_cs, ng_nodename, NGM_IPACCT_COOKIE, 
		    var, ng_cmesg, sizeof(*ng_cmesg) + len);
		if (token_out == -1) {
			warn("ip_account_set: NgSendMsg");
		}
	}
	return ((token_in != -1) && (token_out != -1));
}

#define REPL_SIZE   ((sizeof(struct ng_mesg) + sizeof(struct ip_acct_chunk)))

static int
ip_account_show(int v, int outgoing)
{
	struct ng_ipacct_ainfo ci;
	struct ng_ipacct_hinfo hi;
	int token, nread;
	struct ng_mesg *ng_mesg;
	struct ng_ipacct_mesg *ng_cmesg;
	struct ip_acct_chunk *data;
	char path[NG_PATHLEN + 1];

	ng_cmesg = alloca(sizeof(*ng_cmesg));
	snprintf(ng_cmesg->hname, sizeof(ng_cmesg->hname), 
	    "%s_%s", ng_hookprefix, outgoing ? "out" : "in");

	ng_mesg = alloca(REPL_SIZE);

	if (ip_account_get_info(NGM_IPACCT_CINFO, &ci, sizeof(ci), outgoing)) {
		return (-1);
	}
	if (ip_account_get_info(NGM_IPACCT_HINFO, &hi, sizeof(hi), outgoing)) {
		return (-1);
	}
	for (;;) {
		/* request set of accounting records */
		token = NgSendMsg(ng_cs, ng_nodename, NGM_IPACCT_COOKIE, 
		    NGM_IPACCT_SHOW, ng_cmesg, sizeof(*ng_cmesg));
		if (token == -1) {
			warn("NgSendMsg(NGM_IPACCT_SHOW)");
			return (-1);
		}

        /* read reply */
        if (ng_ready_for_read() != 1)
            return (-1);
        nread = NgRecvMsg(ng_cs, ng_mesg, REPL_SIZE, path);
        if (nread == -1) {
            warn("NgRecvMsg(NG_IPACCT_SHOW)");
            return (-1);
        }

		if (ng_mesg->header.token != token) {
			warnx("NgRecvMsg(NGM_IPACCT_SHOW): token mismatch");
			return (-1);
		}

		data = (struct ip_acct_chunk*)ng_mesg->data;
		if (ng_mesg->header.arglen != sizeof(*data)) {
			warnx("NgRecvMsg(NGM_IPACCT_SHOW): arglen too small");
			return (-1);
		}

		if (data->nrecs == 0)
			break; /* no more data available */
		ip_account_print(data, hi.hi_flags);
	}
	if (ci.ai_th_packets)
		printf(" Accounting exceed threshold by %u packets (%" PRIu64 " bytes)\n",
		    ci.ai_th_packets, ci.ai_th_bytes);
	
	return (0);
}

static int
ip_account_read(char *fname, char *flags)
{
	FILE    *fp;
	struct  ip_acct_chunk *chunk;
	int     n, dflags;

	fp = fopen(fname, "r");
	if (fp == NULL)
		err(1, "fopen");

	chunk = alloca(sizeof(struct ip_acct_chunk));
	if (chunk == NULL)
		err(1, "alloca");

	dflags = strtol(flags, (char **)NULL, 0);

	for (;(feof(fp) == 0); ) {
		n = fread(chunk->recs, sizeof(struct ip_acct_record),
		    NRECS, fp);
		if ((n != NRECS) && ferror(fp)) {
			err(1, "fread");
		}
		chunk->nrecs = n;
		ip_account_print(chunk, dflags); 
	}
	return (0);
}

static int
ip_account_print(struct ip_acct_chunk *pe, int flags)
{
	int i;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	struct ip_acct_record *pr;

	/* quick check */
	if (pe->nrecs == 0)
		return (0);

	/* if binary - write and returns */
	if (wfp != NULL) {
		i = fwrite(pe->recs, sizeof(struct ip_acct_record), 
		    pe->nrecs, wfp);
		if (i != pe->nrecs)
			warn("short write");
		return (i);
	}

	pr = pe->recs;
	for (i = 0; i < pe->nrecs; i++, pr++) {
		if (fl_ipnum) {
			snprintf(src, sizeof(src), "%u", (uint32_t)ntohl(pr->s.r_src.s_addr));
			snprintf(dst, sizeof(dst), "%u", (uint32_t)ntohl(pr->s.r_dst.s_addr));
		} else {
			inet_ntop(AF_INET, &pr->s.r_src, src, sizeof(src));
			inet_ntop(AF_INET, &pr->s.r_dst, dst, sizeof(dst));
		}
		if (flags & HI_VERBOSE_MODE) {
			printf("%s\t%d\t%s\t%d\t%d\t%u\t%" PRIu64,
			    src, ntohs(pr->s.r_sport), 
			    dst, ntohs(pr->s.r_dport),
			    pr->s.r_ip_p, pr->packets, pr->bytes);
		} else {
			printf("%s\t%s\t%u\t%" PRIu64,
			    src, dst, pr->packets, pr->bytes);
		}
		if (flags & HI_SAVE_UID) {
			printf("\t%d", pr->s.r_uid);
		}
		if (flags & HI_SAVE_TIME) {
			printf("\t%ld", (long int)pr->when);
		}
		printf("\n");
	}
	
	return (i);
}

/*
 * Check if control socket ready for read.
 * returns 1 in case of success.
 */
static int
ng_ready_for_read(void)
{
    static int first_call = 1;
    static fd_set rfd, fds;
    static int maxfd;
    static struct timeval tv;
    int     rc;

    if (first_call) {
        /* setup fds */
        maxfd = ng_cs + 1;
        FD_ZERO(&rfd);
        FD_SET(ng_cs, &rfd);
        first_call = 0;
    }
    fds = rfd;
    tv.tv_sec = read_to;

again:
    rc = select(maxfd, &fds, NULL, NULL, &tv);
    if ((rc == -1) && (errno == EINTR))
        goto again;

    switch(rc) {
    case 0: /* timeout occured */
        warnx("control socket not ready for read in %d secs, giving up",
            read_to);
        break;
    case -1: /* oops - error in select! */
        warn("select");
        break;
    default:
        break;
    }

    return (rc);
}

static void
help(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-n][-io] [-w file] [-r file] [-f flags] [-d level] nodename[:hookprefix] command [args]\n", __progname);
	exit (0);
}
