/*-
 * Copyright (c) 2004 Roman V. Palagin <romanp@unshadow.net>
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
 *	 $Id: ng_ipacct_mem.h,v 1.2 2004/11/27 20:40:52 romanp Exp $
 */

/*
 * You have two choices for memory allocation:
 *
 * 	 	MEM_USE_MALLOC 	- use standart malloc/free interface.
 *   	MEM_USE_ZONE	- use zone allocator.
 *
 * Zone allocator believed to be more optimized for small
 * memory allocation of same size. Moreover, UMA zone allocator
 * found in FreeBSD 5.x must be superior!
 *
 */

#if !defined(MME_USE_MALLOC) && !defined(MEM_USE_ZONE)
#define MEM_USE_MALLOC
#endif

#ifdef MEM_USE_MALLOC

MALLOC_DECLARE(M_IPACCT);
MALLOC_DEFINE(M_IPACCT, "IP Accounting", "IP accounting records");

#define HASH_MEMINIT()

#define	HASH_ALLOC()	malloc((u_long)(sizeof(struct ip_acct_chunk)),	\
				M_IPACCT, M_NOWAIT | M_ZERO)

#define HASH_FREE(ptr)		free(ptr, M_IPACCT);

#define HASH_MEMFINI()

#elif defined(MEM_USE_ZONE)
#if __FreeBSD_version >= 500000
#include <vm/uma.h>
static uma_zone_t ip_acct_zone;

#define	HASH_MEMINIT()	ip_acct_zone = uma_zcreate("IpAcct",	  \
			sizeof(struct ip_acct_chunk), NULL, NULL, NULL, NULL, \
			UMA_ALIGN_PTR, 0)

#define HASH_ALLOC()	uma_zalloc(ip_acct_zone, M_NOWAIT | M_ZERO)

#define HASH_FREE(ptr)	uma_zfree(ip_acct_zone, ptr)

#define HASH_MEMFINI()	uma_zdestroy(ip_acct_zone)

#else					/* use FreeBSD 4.x zone allocator */
#include <vm/vm_zone.h>
static vm_zone_t ip_acct_zone;

#define	HASH_MEMINIT()	ip_acct_zone = zinit("IpAcct", \
			sizeof(struct ip_acct_chunk), 0, 0, 1)

#define HASH_ALLOC()	zalloc(ip_acct_zone)

#define HASH_FREE(ptr)	zfree(ip_acct_zone, ptr)

#define HASH_MEMFINI()
#endif					/* __FreeBSD_version */
#endif					/* MEM_USE_XXX */
