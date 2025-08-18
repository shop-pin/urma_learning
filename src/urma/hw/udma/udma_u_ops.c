// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include "udma_u_jfc.h"
#include "udma_u_jfs.h"
#include "udma_u_jfr.h"
#include "udma_u_jetty.h"
#include "udma_u_db.h"
#include "udma_u_ops.h"

/* udma_u_xx_ex interface thanks to rdma-core-master/providers/hns/hns_roce_u.c code. */
static urma_ops_t g_udma_ops = {
	.name = "UDMA_OPS",
	.create_jfc = udma_u_create_jfc,
	.delete_jfc = udma_u_delete_jfc,
	.create_jfs = udma_u_create_jfs,
	.delete_jfs = udma_u_delete_jfs,
	.create_jfr = udma_u_create_jfr,
	.delete_jfr = udma_u_delete_jfr,
	.unimport_jfr = udma_u_unimport_jfr,
	.create_jetty = udma_u_create_jetty,
	.delete_jetty = udma_u_delete_jetty,
	.unimport_jetty = udma_u_unimport_jetty,
	.unbind_jetty = udma_u_unbind_jetty,
	.create_jetty_grp = udma_u_create_jetty_grp,
	.delete_jetty_grp = udma_u_delete_jetty_grp,
	.import_jetty_ex = udma_u_import_jetty_ex,
	.import_jfr_ex = udma_u_import_jfr_ex,
	.bind_jetty_ex = udma_u_bind_jetty_ex,
	.post_jfs_wr = udma_u_post_jfs_wr,
	.post_jfr_wr = udma_u_post_jfr_wr,
	.post_jetty_send_wr = udma_u_post_jetty_send_wr,
	.poll_jfc = udma_u_poll_jfc,
};

static urma_status_t udma_u_init(urma_init_attr_t *conf)
{
	RTE_SET_USED(conf);
	udma_getenv_log_level();
	return URMA_SUCCESS;
}

static urma_status_t udma_u_uninit(void)
{
	return URMA_SUCCESS;
}

static urma_status_t udma_u_query_device(urma_device_t *dev,
					 urma_device_attr_t *dev_attr)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(dev_attr);
	return URMA_SUCCESS;
}

static void udma_u_init_context(struct udma_u_context *udma_ctx,
				struct udma_create_ctx_resp *resp)
{
	udma_ctx->page_size = sysconf(_SC_PAGESIZE);
	udma_ctx->db.id = UDMA_JFC_DB_OFFSET;
	udma_ctx->db.type = UDMA_MMAP_JFC_PAGE;
	udma_ctx->cqe_size = resp->cqe_size;
	udma_ctx->dwqe_enable = resp->dwqe_enable;
	udma_ctx->ue_id = resp->ue_id;
	udma_ctx->chip_id = resp->chip_id;
	udma_ctx->die_id = resp->die_id;
	udma_ctx->jfr_sge = resp->jfr_sge;
}

static urma_context_t *udma_u_create_context(urma_device_t *dev, uint32_t eid_index,
					     int dev_fd)
{
	struct udma_create_ctx_resp resp = {};
	urma_cmd_udrv_priv_t udrv_data = {};
	struct udma_u_context *udma_ctx;
	urma_context_cfg_t cfg = {
		.dev = dev,
		.ops = &g_udma_ops,
		.eid_index = eid_index,
		.dev_fd = dev_fd,
	};

	udma_ctx = (struct udma_u_context *)calloc(1, sizeof(*udma_ctx));
	if (!udma_ctx) {
		UDMA_LOG_ERR("Failed to alloc memory for udma_ctx.\n");
		return NULL;
	}

	if (pthread_mutex_init(&udma_ctx->db_list_mutex, NULL)) {
		UDMA_LOG_ERR("Failed to init db_list_mutex.\n");
		goto err_init_mutex;
	}

	udma_u_set_udata(&udrv_data, NULL, 0, &resp, sizeof(resp));

	if (urma_cmd_create_context(&udma_ctx->urma_ctx, &cfg, &udrv_data)) {
		UDMA_LOG_ERR("Failed to create context.\n");
		goto err_create_ctx;
	}

	udma_u_init_context(udma_ctx, &resp);

	if (udma_u_alloc_db(&udma_ctx->urma_ctx, &udma_ctx->db)) {
		UDMA_LOG_ERR("Failed to alloc jfc db.\n");
		goto err_alloc_db;
	}

	if (udma_u_init_node_tbl(udma_ctx->src_idx_tbl))
		goto err_init_node;

	return &udma_ctx->urma_ctx;

err_init_node:
	udma_u_free_db(&udma_ctx->urma_ctx, &udma_ctx->db);
err_alloc_db:
	(void)urma_cmd_delete_context(&udma_ctx->urma_ctx);
err_create_ctx:
	(void)pthread_mutex_destroy(&udma_ctx->db_list_mutex);
err_init_mutex:
	free(udma_ctx);

	return NULL;
}

static urma_status_t udma_u_delete_context(urma_context_t *ctx)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	urma_status_t ret = URMA_SUCCESS;

	udma_u_uninit_node_tbl(udma_ctx->src_idx_tbl);
	udma_u_free_db(ctx, &udma_ctx->db);

	if (urma_cmd_delete_context(&udma_ctx->urma_ctx)) {
		UDMA_LOG_ERR("udma destroy ctx failed.\n");
		ret = URMA_FAIL;
	}

	(void)pthread_mutex_destroy(&udma_ctx->db_list_mutex);
	free(udma_ctx);

	return ret;
}

urma_provider_ops_t g_udma_provider_ops = {
	.name = "udma",
	.attr = {
		.version = 1,
		.transport_type = URMA_TRANSPORT_UB,
	},
	.match_table = NULL,
	.init = udma_u_init,
	.uninit = udma_u_uninit,
	.query_device = udma_u_query_device,
	.create_context = udma_u_create_context,
	.delete_context = udma_u_delete_context,
};
