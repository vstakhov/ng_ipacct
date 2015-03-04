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
 *	 $Id: ng_ipacct.c,v 1.46 2006/12/05 20:46:04 romanp Exp $
 */

static const char rcs_id[] =
    "@(#) $Id: ng_ipacct.c,v 1.46 2006/12/05 20:46:04 romanp Exp $";

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>			/* XXX for udp_var.h */
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/route.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/netgraph.h>

#include "ng_ipacct.h"

/*
 * FreeBSD version check
 */
#if !defined(__FreeBSD_version) || \
		((__FreeBSD_version >= 500000) && (__FreeBSD_version < 503000)) || \
		((__FreeBSD_version < 440000))
#error "Module not supported on this version of FreeBSD."
#endif

#define ERROUT(x)	{ error = (x); goto done; }

#define DEBUG

#ifdef  DEBUG
#define Dbg_print(lvl, args)	do { if (hip->hi.hi_debug & lvl) printf args; } while (0)
#else
#define Dbg_print(lvl, args)
#endif

#ifndef NTOHS
#define NTOHS(a) (a) = ntohs((a))
#endif

static ng_constructor_t ng_ipacct_constructor;
static ng_rcvmsg_t ng_ipacct_rcvmsg;
static ng_shutdown_t ng_ipacct_shutdown;
static ng_newhook_t ng_ipacct_newhook;
static ng_rcvdata_t ng_ipacct_rcvdata;
static ng_disconnect_t ng_ipacct_disconnect;
static int ng_ipacct_mod_event(module_t mod, int event, void *data);

/* Netgraph node type descriptor */
#if __FreeBSD_version >= 503000
static struct ng_type ng_ipacct_typestruct = {
	.version = NG_ABI_VERSION,
	.name = NG_IPACCT_NODE_TYPE,
	.mod_event = ng_ipacct_mod_event,
	.constructor = ng_ipacct_constructor,
	.rcvmsg = ng_ipacct_rcvmsg,
	.shutdown = ng_ipacct_shutdown,
	.newhook = ng_ipacct_newhook,
	.rcvdata = ng_ipacct_rcvdata,
	.disconnect = ng_ipacct_disconnect,
};
#else
static struct ng_type ng_ipacct_typestruct = {
	NG_VERSION,
	NG_IPACCT_NODE_TYPE,
	ng_ipacct_mod_event,
	ng_ipacct_constructor,
	ng_ipacct_rcvmsg,
	ng_ipacct_shutdown,
	ng_ipacct_newhook,
	NULL,
	NULL,
	ng_ipacct_rcvdata,
	ng_ipacct_rcvdata,
	ng_ipacct_disconnect,
	NULL
};
#endif

NETGRAPH_INIT(ipacct, &ng_ipacct_typestruct);

/* Information we store for each hook on each node */
struct ip_acct_hash;

/*
 * Notes about locking: under FreeBSD 5.x there are can
 * be multiply calls to recvdata() from same node. So we 
 * must protect additions to active hash. No other call
 * can occure simultaneosly.
 *
 * XXX Is it true?
 */
struct ipacct_hook
{
	hook_p  hook;
	node_p  node;
	struct ip_acct_hash *active;	/* active database */
	struct ip_acct_hash *checked;	/* checkpointed database */
	struct ng_ipacct_hinfo hi;	/* hook info */
	struct ng_ipacct_ainfo ai;	/* active info */
	struct ng_ipacct_ainfo ci;	/* checkpointed info */
};

typedef struct ipacct_hook *hinfo_p;

/* Inlcude memory allocation primitives */
#include	"ng_ipacct_mem.h"
/* Inlcude hash manipulation primitives */
#include	"ng_ipacct_hash.h"

static int ng_ipacct_findhook(node_p, struct ng_mesg *, hook_p *, hinfo_p *);

static int ip_account_checkpoint(hinfo_p);
static int ip_account_add(hinfo_p, struct mbuf **);
static void ip_account_stop(hinfo_p);
static int ip_account_show(hinfo_p, struct ng_mesg *);
static int ip_account_chk_mbuf(struct mbuf **, int);

/* XXX should be somewhere in ng_ipacct_hash.c */
static uid_t pcb_get_cred(struct ip_acct_stream *r, struct inpcbinfo *pcbinfo);
static int ip_hash_make_rec(hinfo_p hip, struct mbuf **m, int *plen,
    struct ip_acct_stream *r);
static struct ip_acct_chunk *ip_hash_getnext(struct ip_acct_hash *h);

static int
ng_ipacct_mod_event(module_t mod, int event, void *data)
{
	switch (event) {
	case MOD_LOAD:
		HASH_MEMINIT();
#ifdef VERBOSE
		printf("NG_ipacct: module loaded.\n");
		printf("NG_ipacct: version %s, API version %d\n",
		    "$Revision: 1.46 $", NGM_IPACCT_APIVER);
#endif
		break;
	case MOD_UNLOAD:
		HASH_MEMFINI();
#ifdef VERBOSE
		printf("NG_ipacct: module unloaded.\n");
#endif
		break;
	}

	return (0);
}

/*
 * Called at node creation
 */
#if __FreeBSD_version >= 503000
static int
ng_ipacct_constructor(node_p nodep)
#else
static int
ng_ipacct_constructor(node_p * nodep)
#endif
{
#if __FreeBSD_version < 503000
	int     error = 0;

	/*
	 * Call the 'generic' (ie, superclass) node constructor 
	 */
	if ((error = ng_make_node_common(&ng_ipacct_typestruct, nodep)))
		return (error);
#endif
	return (0);
}

/*
 * Called at hook connection
 */
static int
ng_ipacct_newhook(node_p node, hook_p hook, const char *name)
{
	hinfo_p hip;
	int     error;

	MALLOC(hip, hinfo_p, sizeof(*hip), M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (hip == NULL)
		return (ENOMEM);

	/*
	 * allocate space for hash of accounting records 
	 */
	if ((error = ip_hash_init(&hip->active)))
		return (error);

	hip->checked = NULL;
	hip->hook = hook;
	hip->node = node;
	hip->ai.ai_start = time_second;
	/*
	 *  set DLT to EN10MB (for compatibility reasons), can be changed 
	 *  via ipacctctl <..> dlt DLT
	 */
	hip->hi.hi_dlt = DLT_EN10MB;

	if (!strncmp(name + strlen(name) - 3, "_in", 3))
		hip->hi.hi_flags |= HI_INCOMING_HOOK;
	NG_HOOK_SET_PRIVATE(hook, hip);
	hip->hi.hi_debug = 0;
#ifdef VERBOSE
	printf("NG_ipacct: hook %s attached (type %s)\n",
	    name,
	    (hip->hi.hi_flags & HI_INCOMING_HOOK) ? "incoming" : "outgoing");
#endif
	return (0);
}

/*
 * Get a netgraph control message.
 */
#if __FreeBSD_version >= 503000
static int
ng_ipacct_rcvmsg(node_p node, item_p item, hook_p lasthook)
#else
static int
ng_ipacct_rcvmsg(node_p node, struct ng_mesg *msg,
    const char *retaddr, struct ng_mesg **rptr)
#endif
{
	struct ng_mesg *resp = NULL;
	int     error = 0;
	hook_p  h;
	hinfo_p hip;
	struct ng_ipacct_mesg *msg1;

#if __FreeBSD_version >= 503000
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
#endif

	/*
	 * Deal with message according to cookie and command 
	 */
	switch (msg->header.typecookie) {
	case NGM_IPACCT_COOKIE:
		switch (msg->header.cmd) {
		case NGM_IPACCT_VINFO:	/* return API and RCS versions info */
			{
				struct ng_ipacct_vinfo *vi;

				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ng_ipacct_vinfo), M_NOWAIT);
				vi = (struct ng_ipacct_vinfo *) resp->data;
				vi->vi_api_version = NGM_IPACCT_APIVER;
				strncpy(vi->vi_kernel_id, rcs_id,
				    MAXKERNIDLEN);
				break;
			}
		case NGM_IPACCT_HINFO:	/* return hook info */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_HINFO message received for %s\n",
					NG_HOOK_NAME(h)));
				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ng_ipacct_hinfo), M_NOWAIT);
				if (!resp)
					ERROUT(ENOMEM);
				*(struct ng_ipacct_hinfo *) resp->data =
				    hip->hi;

				break;
			}
		case NGM_IPACCT_AINFO:	/* return active database info */
		case NGM_IPACCT_CINFO:	/* return checkpointed database info */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_A(C)INFO message received for %s\n",
					NG_HOOK_NAME(h)));
				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ng_ipacct_ainfo), M_NOWAIT);
				if (!resp)
					ERROUT(ENOMEM);

				if (msg->header.cmd == NGM_IPACCT_AINFO)
					*(struct ng_ipacct_ainfo *) resp->
					    data = hip->ai;
				else
					*(struct ng_ipacct_ainfo *) resp->
					    data = hip->ci;

				break;
			}
		case NGM_IPACCT_STHRS:	/* set threshold */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_STHRS message received for %s\n",
					NG_HOOK_NAME(h)));
				msg1 = (struct ng_ipacct_mesg *) (msg->data);
				hip->hi.hi_threshold = *(int *) (msg1->data);
				hip->hi.hi_thrs_when = 0;
				break;
			}
		case NGM_IPACCT_DLEVEL:	/* set debug level */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_DLEVEL message received for %s\n",
					NG_HOOK_NAME(h)));
				msg1 = (struct ng_ipacct_mesg *) (msg->data);
				hip->hi.hi_debug = *(int *) (msg1->data);
				break;
			}
		case NGM_IPACCT_SFLAGS:	/* set bits in hi_flags */
		case NGM_IPACCT_CFLAGS:	/* clear bits in hi_flags */
			{
				int     bits;

				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_(S|C)FLAGS message received for %s\n",
					NG_HOOK_NAME(h)));
				msg1 = (struct ng_ipacct_mesg *) (msg->data);
				bits = *(int *) (msg1->data);
				if (msg->header.cmd == NGM_IPACCT_SFLAGS)
					hip->hi.hi_flags |= bits;
				else
					hip->hi.hi_flags &= ~bits;

				break;
			}
		case NGM_IPACCT_SETDLT:	/* set data-link type */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_SETDLT message received for %s\n",
					NG_HOOK_NAME(h)));
				msg1 = (struct ng_ipacct_mesg *) (msg->data);
				hip->hi.hi_dlt = *(int *) (msg1->data);

				break;
			}
		case NGM_IPACCT_CHECK:	/* checkpoint active accounting */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_CHECK message received for %s\n",
					NG_HOOK_NAME(h)));
				error = ip_account_checkpoint(hip);

				break;
			}
		case NGM_IPACCT_CLEAR:	/* clear checkpoint database */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_CLEAR message received for %s\n",
					NG_HOOK_NAME(h)));
				ip_hash_clear(&hip->checked);
				bzero(&hip->ci, sizeof(hip->ci));


				break;
			}
		case NGM_IPACCT_SHOW:	/* get accounting out of the kernel into the
					 * userspace */
			{
				error =
				    ng_ipacct_findhook(node, msg, &h, &hip);
				if (error)
					ERROUT(error);
				Dbg_print(DBG_GEN,
				    ("NGM_IPACCT_SHOW message received for %s\n",
					NG_HOOK_NAME(h)));
				NG_MKRESPONSE(resp, msg,
				    sizeof(struct ip_acct_chunk), M_NOWAIT);
				if (!resp)
					ERROUT(ENOMEM);

				error = ip_account_show(hip, resp);

				break;
			}

		default:
			ERROUT(EINVAL);	/* unknown command */
			break;
		}
		break;

	default:
		ERROUT(EINVAL);		/* unknown cookie type */
		break;
	}

	/*
	 * Take care of synchronous response, if any 
	 */
#if __FreeBSD_version >= 503000
	NG_RESPOND_MSG(error, node, item, resp);
#else
	if (rptr)
		*rptr = resp;
	else if (resp)
		FREE(resp, M_NETGRAPH);
#endif
      done:

	NG_FREE_MSG(msg);

	return (error);
}

#if __FreeBSD_version >= 503000
static int
ng_ipacct_rcvdata(hook_p hook, item_p item)
#else
static int
ng_ipacct_rcvdata(hook_p hook, struct mbuf *m, meta_p meta)
#endif
{
	const hinfo_p hip = NG_HOOK_PRIVATE(hook);
	int     error = 0;

#if __FreeBSD_version >= 503000
	struct mbuf *m;

	m = NGI_M(item);
#endif

	switch (hip->hi.hi_dlt) {
	case DLT_EN10MB:		/* Ethernet */
		{
			struct ether_header *eh;

			Dbg_print(DBG_DLT,
			    ("Ethernet frame, m_pkthdr.len = %d, m_len = %d\n",
				m->m_pkthdr.len, m->m_len));
			if ((error =
				ip_account_chk_mbuf(&m,
				    sizeof(struct ether_header))))
				break;

			eh = mtod(m, struct ether_header *);

			/*
			 * make sure this is IP frame 
			 */
			NTOHS(eh->ether_type);
			Dbg_print(DBG_DLT, ("Ethernet frame type = 0x%04x\n",
				eh->ether_type));
			switch (eh->ether_type) {
			case ETHERTYPE_IP:
				/*
				 * skip ethernet header 
				 */
				m_adj(m, sizeof(struct ether_header));
				break;
			default:
				error = EINVAL;	/* XXX */
				break;
			}

			break;
		}
	case INT_DLT_NGGIF:		/* ng_gif lower hook */
		{
			sa_family_t af;

			Dbg_print(DBG_DLT,
			    ("ng_gif frame, m_pkthdr.len = %d, m_len = %d\n",
				m->m_pkthdr.len, m->m_len));
			if ((error =
				ip_account_chk_mbuf(&m, sizeof(sa_family_t))))
				break;
			af = *(mtod(m, sa_family_t *));

			/*
			 * make sure this is IP packet 
			 */
			Dbg_print(DBG_DLT, ("ng_gif frame AF = 0x%04x\n", af));
			switch (af) {
			case AF_INET:
				/*
				 * skip AF glue 
				 */
				m_adj(m, sizeof(sa_family_t));
				break;
			default:
				error = EINVAL;	/* XXX */
				break;
			}

			break;
		}
	case DLT_RAW:			/* Raw IP packet */
		{
			Dbg_print(DBG_DLT,
			    ("IP packet, m_pkthdr.len = %d, m_len = %d\n",
				m->m_pkthdr.len, m->m_len));
			break;
		}
	default:
		error = EINVAL;
		break;
	}

	if (!error)
		error = ip_account_chk_mbuf(&m, sizeof(struct ip));

	if (!error) {
		Dbg_print(DBG_DLT,
		    ("IP packet, m_pkthdr.len = %d, m_len = %d\n",
			m->m_pkthdr.len, m->m_len));
		error = ip_account_add(hip, &m);
	}
#if __FreeBSD_version >= 503000
	NG_FREE_ITEM(item);
#else
	if (m)
		NG_FREE_DATA(m, meta);
	else
		NG_FREE_META(meta);
#endif

	return (error);
}

/*
 * Do local shutdown processing..
 */
static int
ng_ipacct_shutdown(node_p node)
{
#if __FreeBSD_version >= 503000
	NG_NODE_UNREF(node);
#else
	node->flags |= NG_INVALID;
	ng_cutlinks(node);
	ng_unname(node);
	ng_unref(node);
#endif
	return (0);
}

/*
 * Hook disconnection
 *
 * Removal of the last link destroys the node
 */
static int
ng_ipacct_disconnect(hook_p hook)
{
	const hinfo_p hip = NG_HOOK_PRIVATE(hook);

	ip_account_stop(hip);
	NG_HOOK_SET_PRIVATE(hook, NULL);
	FREE(hip, M_NETGRAPH);
#ifdef VERBOSE
	printf("NG_ipacct: disconnect hook %s\n", NG_HOOK_NAME(hook));
#endif
	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0) &&
	    (NG_NODE_IS_VALID(NG_HOOK_NODE(hook)))) {
#ifdef VERBOSE
		printf
		    ("NG_ipacct: all hooks disconnected - remove whole node\n");
#endif
#if __FreeBSD_version >= 503000
		ng_rmnode_self(NG_HOOK_NODE(hook));
#else
		ng_rmnode(hook->node);
#endif
	}

	return (0);
}

static int
ng_ipacct_findhook(node_p node, struct ng_mesg *msg, hook_p * h, hinfo_p * hip)
{
	struct ng_ipacct_mesg *msg1;

	/*
	 * Sanity check 
	 */
	if (msg->header.arglen == 0) {
		return (EINVAL);
	}
	msg1 = (struct ng_ipacct_mesg *) msg->data;
	/*
	 * Find hook.
	 * XXX we need some way to check how long
	 * msg1->hname is.
	 */
	if ((*h = ng_findhook(node, msg1->hname)) == NULL) {
		return (ENOENT);
	}
	if ((*hip = NG_HOOK_PRIVATE(*h)) == NULL) {
		return (ENOENT);	/* XXX */
	}

	return (0);
}

/***********************************************************
 * IP accounting functions                                 *
 ***********************************************************/

/*
 * Add acounting record to active hash. m points to mbuf chain 
 * with link-layer header stripped.
 */
static int
ip_account_add(hinfo_p hip, struct mbuf **m)
{

	struct ip_acct_record *ipe;
	struct ip_acct_stream r;
	int     plen, error;
	u_int32_t slot;

	if (hip->active == NULL) {
		return (ENOMEM);
	}

	/*
	 * Try to fill *rec 
	 */
	bzero(&r, sizeof(r));
	if ((error = ip_hash_make_rec(hip, m, &plen, &r))) {
		return (error);
	}

	hip->hi.hi_packets++;
	hip->hi.hi_bytes += plen;

	slot = ip_hash(hip, &r);
	ipe = ip_hash_lookup_or_insert(hip->active, slot, &r,
	    &hip->hi.hi_records,
	    !(hip->hi.hi_records >= hip->hi.hi_threshold));

	if (ipe) {
		/*
		 * ipe already contains stream information, we just need
		 * increment bytes/packets counters.
		 */
		ipe->bytes += plen;
		ipe->packets++;
	} else {
		/*
		 * Threshold was exceeded or some errors occured, increment 
		 * threshold counters.
		 */
		hip->ai.ai_th_packets++;
		hip->ai.ai_th_bytes += plen;
		hip->hi.hi_thrs_when = time_second;
		return (ENOMEM);
	}

	hip->ai.ai_packets++;
	hip->ai.ai_bytes += plen;
	hip->ai.ai_last = time_second;

	return (0);
}

/*
 * Checkpoint active hash. Called at splnet(?).
 * Must be executed as fast as possible.
 */
static int
ip_account_checkpoint(hinfo_p hip)
{
	time_t  ts;

	int     spl;

	/*
	 * sanity checks 
	 */
	if (hip->active == NULL)
		return (EINVAL);
	if (hip->checked != NULL)
		return (EINVAL);

	spl = splhigh();		/* XXX Do we realy need this? */

	hip->checked = hip->active;
	bzero(&hip->ci, sizeof(struct ng_ipacct_ainfo));
	bcopy(&hip->ai, &hip->ci, sizeof(struct ng_ipacct_ainfo));
	ts = time_second;
	hip->ci.ai_last = ts;
	bzero(&hip->ai, sizeof(struct ng_ipacct_ainfo));
	hip->ai.ai_start = ts;
	ip_hash_init(&hip->active);
	hip->hi.hi_records = 0;

	splx(spl);

	if (hip->active == NULL)
		return (ENOMEM);

	return (0);
}

/*
 * Copy accounting chunks to user space. For now we
 * copy one chunk per NGM_IPACCT_SHOW message.
 */
static int
ip_account_show(hinfo_p hip, struct ng_mesg *resp)
{
	struct ip_acct_chunk *pe, *outpe;

	if (hip->checked == NULL) {
		return (ENOENT);
	}

	if (hip->ci.ai_packets == 0)
		return (0);

	outpe = (struct ip_acct_chunk *) resp->data;
	outpe->nrecs = 0;
	pe = ip_hash_getnext(hip->checked);
	if (pe != NULL)
		bcopy(pe, outpe, sizeof(*outpe));

	return (0);
}

static void
ip_account_stop(hinfo_p hip)
{
	/*
	 * clear checked database 
	 */
	ip_hash_clear(&hip->checked);
	/*
	 * clear active database 
	 */
	hip->checked = hip->active;
	hip->active = NULL;
	ip_hash_clear(&hip->checked);
}

static int
ip_account_chk_mbuf(struct mbuf **m, int min_len)
{
	/*
	 * Make sure packet large enough to contains min_len bytes 
	 */
	if ((*m)->m_pkthdr.len < min_len) {
		return (EINVAL);
	}

	if (((*m)->m_len < min_len) && ((*m = m_pullup(*m, min_len)) == NULL)) {
		return (ENOBUFS);
	}
	return (0);
}

static int
ip_hash_make_rec(hinfo_p hip, struct mbuf **m, int *plen,
    struct ip_acct_stream *r)
{
	register struct ip *ip;
	int     hlen, error;

	ip = mtod(*m, struct ip *);

	/*
	 * Sanity checks:
	 *
	 * 1. Check version
	 * 2. Check for minimum header length
	 * 3. Verify checksum (?)
	 */
	if (ip->ip_v != IPVERSION) {
		return (EINVAL);
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		return (EINVAL);
	}

	r->r_src = ip->ip_src;
	r->r_dst = ip->ip_dst;

	/*
	 * save packet length 
	 */
	NTOHS(ip->ip_len);
	*plen = ip->ip_len;

	if (!(hip->hi.hi_flags & HI_VERBOSE_MODE)) {
		return (0);
	}

	r->r_ip_p = ip->ip_p;

	NTOHS(ip->ip_off);
	/*
	 * XXX NOTE: only first fragment of fragmented TCP, UDP and 
	 * ICMP packet will be recorded with proper s_port and d_port.
	 * Folowing fragments will be recorded simply as IP packet with
	 * ip_proto = ip->ip_p and s_port, d_port set to zero. 
	 * I know, it looks like bug. But I don't want to re-implement 
	 * ip packet assebmling here. Anyway, (in)famous trafd works this way -
	 * and nobody complains yet :)
	 */
	if (ip->ip_off & IP_OFFMASK) {
		return (0);
	}

	/*
	 * skip IP header 
	 */
	m_adj(*m, hlen);

	error = 0;

	switch (r->r_ip_p) {
	case IPPROTO_TCP:
		if ((error =
			ip_account_chk_mbuf(m, sizeof(struct tcphdr))) != 0) {
			/*
			 * looks like truncated TCP packet 
			 */
			break;
		}
		r->r_ports = *(mtod(*m, u_int32_t *));
		if (hip->hi.hi_flags & HI_SAVE_UID)
			r->r_uid = pcb_get_cred(r, &tcbinfo);
		break;
	case IPPROTO_UDP:
		if ((error =
			ip_account_chk_mbuf(m, sizeof(struct udphdr))) != 0) {
			/*
			 * looks like truncated UDP packet 
			 */
			break;
		}
		r->r_ports = *(mtod(*m, u_int32_t *));
		if (hip->hi.hi_flags & HI_SAVE_UID)
			r->r_uid = pcb_get_cred(r, &udbinfo);
		break;
	case IPPROTO_ICMP:
		{
			struct icmp *icmp;

			if ((error = ip_account_chk_mbuf(m, ICMP_MINLEN)) != 0) {
				/*
				 * looks like truncated ICMP packet 
				 */
				break;
			}

			icmp = mtod(*m, struct icmp *);

			r->r_ports =
			    (icmp->icmp_code << 24) | (icmp->icmp_type << 8);
			break;
		}
	}

	return (error);
}

static struct ip_acct_chunk *
ip_hash_getnext(struct ip_acct_hash *h)
{
	static int curindex = -1;
	static struct ip_acct_chunk *curent = NULL;
	struct ip_acct_chunk *ipe;

	if (curent == NULL) {
		do {
			curindex++;
			if (curindex > (NBUCKETS - 1)) {
				/*
				 * no more data available, reset walkers 
				 */
				curindex = -1;
				curent = NULL;
				return (NULL);
			}
			/*
			 * start with next bucket 
			 */
			curent = SLIST_FIRST(&(h[curindex].head));
		} while (curent == NULL);
	}
	ipe = curent;
	curent = SLIST_NEXT(curent, next);

	return (ipe);
}

static  uid_t
pcb_get_cred(struct ip_acct_stream *r, struct inpcbinfo *pcbinfo)
{
	struct inpcb *pcb = NULL;
	struct in_addr ina;
	u_short port;
	int     i;
	uid_t   res;

	INP_HASH_RLOCK(pcbinfo);
	for (i = 0, ina = r->r_dst, port = r->r_dport; i < 2; i++) {
#if __FreeBSD_version >= 700110
		pcb = in_pcblookup_local(pcbinfo, ina, port, 1, NOCRED);
#else
		pcb = in_pcblookup_local(pcbinfo, ina, port, 1);
#endif
		if ((pcb != NULL) && (pcb->inp_laddr.s_addr == ina.s_addr)) {
			break;
		}
		ina = r->r_src;
		port = r->r_sport;
		pcb = NULL;
	}
	res = -1;
	if ((pcb != NULL) &&
	    (pcb->inp_socket != NULL) && (pcb->inp_socket->so_cred != NULL)) {
		res = pcb->inp_socket->so_cred->cr_uid;
	}
	INP_HASH_RUNLOCK(pcbinfo);
	return res;
}
