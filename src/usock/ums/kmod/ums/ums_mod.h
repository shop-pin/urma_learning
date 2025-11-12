/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS module header file
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#ifndef UMS_MOD_H
#define UMS_MOD_H

#include <net/genetlink.h>
#include <net/sock.h>

#include <linux/compiler.h> /* __aligned */
#include <linux/socket.h>
#include <linux/types.h>

#include <ub/urma/ubcore_uapi.h>
#include "ums_core.h"

#define UMS_RELEASE 0
#define UMS_3_BITS 3

/* socket level for SMC */
#if !defined SOL_SMC
#define SOL_SMC 286
#endif

extern struct proto g_ums_proto;
extern struct proto g_ums_proto6;
extern struct ums_sysctl_config g_ums_sysctl_conf;
extern struct ums_sys_tuning_config g_ums_sys_tuning_config;

#ifdef ATOMIC64_INIT
#define KERNEL_HAS_ATOMIC64
#endif

extern struct workqueue_struct *g_ums_tcp_ls_wq;
extern struct workqueue_struct *g_ums_hs_wq;    /* wq for handshake work */
extern struct workqueue_struct *g_ums_close_wq; /* wq for close work */

extern u8 g_local_systemid[UMS_SYSTEMID_LEN]; /* unique system identifier */

static inline u64 ntohll(u64 x)
{
	return be64_to_cpu(x);
}

static inline u64 htonll(u64 x)
{
	return cpu_to_be64(x);
}

/* convert an u32 value into network byte order */
static inline void hton24(u8 *net, u32 host)
{
	__be32 t;
	t = cpu_to_be32(host);
	(void)memcpy(net, ((u8 *)&t) + 1, UMS_3_BITS);
}

/* convert 3 bytes in network byte order into host byte order */
static inline u32 ntoh24(u8 *net)
{
	__be32 t = 0;
	(void)memcpy(((u8 *)&t) + 1, net, UMS_3_BITS);
	return be32_to_cpu(t);
}

void ums_close_non_accepted(struct sock *sk);
#endif /* UMS_MOD_H */
