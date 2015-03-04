/*-
 * Copyright (c) 2001-2004 Roman V. Palagin <romanp@unshadow.net>
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
 *	 $Id: ng_ipacct.h,v 1.24 2005/03/10 07:54:36 romanp Exp $
 */

#define NG_IPACCT_NODE_TYPE	"ipacct"
#define NGM_IPACCT_COOKIE	979555896
#ifdef MEM_USE_ZONE
#define NGM_IPACCT_APIVER 3
#else
#define NGM_IPACCT_APIVER	2
#endif

/* 
 * How many accounting records we will store in
 * each allocation chunk. This is also defines
 * how mant record at once will be transfered to
 * user level.
 */
#define	NRECS			50

/* Netgraph commands understood by ipacct node */
enum
{
	NGM_IPACCT_HINFO = 1,		/* get hook info */
	NGM_IPACCT_AINFO,		/* get active accounting info */
	NGM_IPACCT_CINFO,		/* get checkpointed accounting info */
	NGM_IPACCT_CHECK,		/* checkpoint accounting */
	NGM_IPACCT_SHOW,		/* get checkpointed data */
	NGM_IPACCT_CLEAR,		/* clear checkpointed database */
	NGM_IPACCT_STHRS,		/* set threshold */
	NGM_IPACCT_SETDLT,		/* set data-link type */
#define INT_DLT_NGGIF   1000		/* Internal DLT type for ng_gif */
	NGM_IPACCT_DLEVEL,		/* set debug level. 0 - turn it off.
					 * this is per-node variable */
#define	DBG_GEN			0x00000001
#define DBG_IP			0x00000002
#define DBG_HASH		0x00000004
#define DBG_DLT			0x00000008
	NGM_IPACCT_SFLAGS,		/* set bits in hi_flags */
	NGM_IPACCT_CFLAGS,		/* clear bits in hi_flags */
	NGM_IPACCT_VINFO,		/* get version info */
};

/* This structure is returned by the NGM_IPACCT_HINFO command */
struct ng_ipacct_hinfo
{
	u_int32_t hi_packets;		/* total number of accounted packets */
	u_int64_t hi_bytes;		/* total number of accounted bytes */
	u_int32_t hi_records;		/* total number of hash records */
	u_int32_t hi_debug;		/* debug level */
	u_int32_t hi_threshold;		/* max. number of hash records */
	time_t  hi_thrs_when;		/* when threshold was exceeded */
	u_int32_t hi_flags;		/* various flags */
	u_int32_t hi_dlt;		/* Data Link Type, DLT_XXX */
};

/*
 * This is flags for hi_flags
 */
#define	HI_INCOMING_HOOK	0x00000001	/* Incoming hook */
#define HI_VERBOSE_MODE		0x00000002	/* save IP proto and ports */
#define HI_SAVE_UID		0x00000004	/* save uid */
#define	HI_SAVE_TIME		0x00000008	/* save time when record was created */

/* 
 * This structure is returned by the NGM_IPACCT_AINFO 
 * and NGM_IPACCT_CINFO commands 
 */
struct ng_ipacct_ainfo
{
	u_int32_t ai_packets;		/* number of accounted packets */
	u_int64_t ai_bytes;		/* total number of accounted bytes */
	u_int32_t ai_th_packets;	/* number of packets after threshold */
	u_int64_t ai_th_bytes;		/* number of bytes after threshold */
	time_t  ai_start;		/* when database was created */
	time_t  ai_last;		/* when last packet was added */
};

/* 
 * This structure is returned by the NGM_IPACCT_VINFO command
 */
#define	MAXKERNIDLEN	512

struct ng_ipacct_vinfo
{
	u_int32_t vi_api_version;	/* API version */
	char    vi_kernel_id[MAXKERNIDLEN];	/* kernel module RCS id */
};

/* unique data, which identifies accounted stream */
struct ip_acct_stream
{
	struct in_addr r_src;
	struct in_addr r_dst;
	union
	{
		struct
		{
			u_char  proto;
			u_char  pad[3];
		} i;
		u_int32_t all;
	} misc;
	union
	{
		struct
		{
			u_int16_t s_port;
			u_int16_t d_port;
		} dir;
		u_int32_t both;
	} ports;
	uid_t   r_uid;
};

#define	r_ip_p	misc.i.proto
#define r_misc	misc.all
#define r_ports	ports.both
#define r_sport	ports.dir.s_port
#define r_dport	ports.dir.d_port

/* accounting record. contains stream info + accounting info */
struct ip_acct_record
{
	struct ip_acct_stream s;
	u_int32_t packets;
	time_t  when;
	u_int64_t bytes;
};

/* accounting chunk. contains several records. */
struct ip_acct_chunk
{
#ifdef MEM_USE_ZONE
	struct ip_acct_chunk *z_rsvd1;
	struct ip_acct_chunk *z_rsvd2;
#endif
	int     nrecs;			/* number of records in this chunk */
	struct ip_acct_record recs[NRECS];
	SLIST_ENTRY (ip_acct_chunk) next;	/* linked list of chunks */
};

#define	MAX_HNAME_LEN	32

/* ng_ipacct message */
struct ng_ipacct_mesg
{
	char    hname[MAX_HNAME_LEN];	/* ASCIIZ hook name */
	char    data[0];		/* data starts here */
};
