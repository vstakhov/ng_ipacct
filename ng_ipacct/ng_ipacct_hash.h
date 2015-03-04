/*-
 * Copyright (c) 2002,2004 Roman V. Palagin <romanp@unshadow.net>
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
 *	 $Id: ng_ipacct_hash.h,v 1.6 2004/11/27 20:35:19 romanp Exp $
 */

#define	NBUCKETS	(512)		/* must be power of 2 */

#include <sys/lock.h>
#include <sys/rmlock.h>

#define	NG_IPACCT_HASH3(faddr, fport, lport)\
        ((faddr) ^ ((faddr) >> 16) ^ ntohs((lport) ^ (fport)))
#define NG_IPACCT_HASH1(faddr)\
        ((faddr ^ (faddr >> 23) ^ (faddr >> 17)))

struct ip_acct_hash {
	struct rmlock bl;
	SLIST_HEAD (, ip_acct_chunk) head;
};

/* #define HASH_DEBUG */

static __inline int
ip_hash_init(struct ip_acct_hash **h)
{
	int i;
	struct ip_acct_hash *ph;

	MALLOC(*h, struct ip_acct_hash *,
	    NBUCKETS * sizeof(struct ip_acct_hash),
	    M_NETGRAPH, M_NOWAIT | M_ZERO);
	if (*h == NULL)
		return (ENOMEM);

	ph = *h;
	for (i = 0; i < NBUCKETS; i++) {
		rm_init(&ph[i].bl, "ng_ipacct hash lock");
	}

	return (0);
}

/* this is hash manipulating functions */

static __inline struct ip_acct_record *
ip_hash_lookup_or_insert(struct ip_acct_hash *h, int slot,
    struct ip_acct_stream *s, u_int32_t *nrecs, int ok_to_insert)
{
	struct ip_acct_chunk *pe, *lastpe;
	struct ip_acct_record *pr;
	int i;
	struct rm_priotracker track;

#ifdef HASH_DEBUG
	int nchunk = 0;

#endif

	pe = lastpe = NULL;
	rm_rlock(&h[slot].bl, &track);
	SLIST_FOREACH(pe, &(h[slot].head), next) {
		lastpe = pe;
		for (i = 0; i < pe->nrecs; i++) {
			if (bcmp(s, &pe->recs[i].s,
			    sizeof(struct ip_acct_stream)) == 0) {
				rm_runlock(&h[slot].bl, &track);
				return (&pe->recs[i]);
			}
		}
#ifdef HASH_DEBUG
		nchunk++;
#endif
	}
	rm_runlock(&h[slot].bl, &track);
#ifdef HASH_DEBUG
	if (nchunk)
		nchunk--;
#endif
	/*
	 * stream is not in hash. Add it if we allowed to do so.
	 */
	if (ok_to_insert) {

		rm_wlock(&h[slot].bl);
		if (lastpe != NULL && SLIST_NEXT(lastpe, next) != NULL) {
			/*
			 * It has been changed, need to scan again
			 */
			pe = lastpe;
			while (pe != NULL) {
				lastpe = pe;
				for (i = 0; i < pe->nrecs; i++) {
					if (bcmp(s, &pe->recs[i].s,
					    sizeof(struct ip_acct_stream))
					    == 0) {
						rm_wunlock(&h[slot].bl);
						return (&pe->recs[i]);
					}
				}
				pe = SLIST_NEXT(pe, next);
			}
		}
		/*
		 * This is first chunk in slot or no
		 * more space left in current chunk ?
		 */
		if ((lastpe == NULL) || (lastpe->nrecs >= NRECS)) {
#ifdef HASH_DEBUG
			printf("%s new chunk (%d bytes)\n",
			    (lastpe == NULL) ? "Allocate" : "Add",
			    sizeof(*pe));
#endif
			/*
			 * allocate new accounting chunk
			 */
			if ((pe = HASH_ALLOC()) == NULL) {
				rm_wunlock(&h[slot].bl);
				return (NULL);
			}
			if (lastpe == NULL)
				SLIST_INSERT_HEAD(&(h[slot].head), pe, next);
			else
				SLIST_NEXT(lastpe, next) = pe;
			lastpe = pe;
		}
#ifdef HASH_DEBUG
		printf("Stream added in hash %p at slot %d, chunk %d, nr %d\n",
		    h, slot, nchunk, lastpe->nrecs);
#endif
		lastpe->nrecs++;
		pr = &(lastpe->recs[lastpe->nrecs - 1]);
		pr->when = time_second;
		bcopy(s, &pr->s, sizeof(pr->s));
		(*nrecs)++;
		rm_wunlock(&h[slot].bl);
		return (pr);
	} else {
		return (NULL);
	}
}

static __inline void
ip_hash_clear(struct ip_acct_hash **h)
{
	int i;
	struct ip_acct_chunk *ipe, *nxt;
	struct ip_acct_hash *ph = *h;

	/*
	 * sanity check
	 */
	if (*h == NULL)
		return;

	/*
	 * walk down through *next and free all memory
	 */
	for (i = 0; i < NBUCKETS; i++) {
		rm_wlock(&ph[i].bl);
		for (ipe = SLIST_FIRST(&((*h)[i].head)); ipe; ipe = nxt) {
			nxt = SLIST_NEXT(ipe, next);
			HASH_FREE(ipe);
		}
		rm_wunlock(&ph[i].bl);
		rm_destroy(&ph[i].bl);
	}
	FREE(*h, M_NETGRAPH);
	*h = NULL;
}

static __inline u_int32_t
ip_hash(hinfo_p hip, struct ip_acct_stream *r)
{
	u_int32_t faddr;
	u_int32_t slot;

	faddr = (hip->hi.hi_flags & HI_INCOMING_HOOK) ?
	    r->r_src.s_addr : r->r_dst.s_addr;

	if (hip->hi.hi_flags & HI_VERBOSE_MODE) {
		slot =
		    NG_IPACCT_HASH3(faddr, r->r_sport,
		    r->r_dport) & (NBUCKETS - 1);
	} else {
		slot = NG_IPACCT_HASH1(faddr) & (NBUCKETS - 1);
	}

	return (slot);
}
