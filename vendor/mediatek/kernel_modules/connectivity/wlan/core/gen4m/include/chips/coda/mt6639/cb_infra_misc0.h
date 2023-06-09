/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 MediaTek Inc.
 */

#ifndef __CB_INFRA_MISC0_REGS_H__
#define __CB_INFRA_MISC0_REGS_H__

#include "hal_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CB_INFRA_MISC0_BASE \
	0x70026000

#define CB_INFRA_MISC0_CONN2AP_GALS_SLV_DBG_ADDR \
	(CB_INFRA_MISC0_BASE + 0X000)
#define CB_INFRA_MISC0_AP2CONN_GALS_MST_DBG_ADDR \
	(CB_INFRA_MISC0_BASE + 0X008)
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_ADDR \
	(CB_INFRA_MISC0_BASE + 0x554)
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_ADDR \
	(CB_INFRA_MISC0_BASE + 0x558)


#define CB_INFRA_MISC0_CONN2AP_GALS_SLV_DBG_CONN2AP_GALS_SLV_DBG_OUT_ADDR \
	CB_INFRA_MISC0_CONN2AP_GALS_SLV_DBG_ADDR
#define CB_INFRA_MISC0_CONN2AP_GALS_SLV_DBG_CONN2AP_GALS_SLV_DBG_OUT_MASK \
	0xFFFFFFFF
#define CB_INFRA_MISC0_CONN2AP_GALS_SLV_DBG_CONN2AP_GALS_SLV_DBG_OUT_SHFT \
	0

#define CB_INFRA_MISC0_AP2CONN_GALS_MST_DBG_AP2CONN_GALS_MST_DBG_OUT_ADDR \
	CB_INFRA_MISC0_AP2CONN_GALS_MST_DBG_ADDR
#define CB_INFRA_MISC0_AP2CONN_GALS_MST_DBG_AP2CONN_GALS_MST_DBG_OUT_MASK \
	0xFFFFFFFF
#define CB_INFRA_MISC0_AP2CONN_GALS_MST_DBG_AP2CONN_GALS_MST_DBG_OUT_SHFT \
	0

#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg1_ADDR \
	CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_ADDR
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg1_MASK \
	0xFFFF0000
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg1_SHFT \
	16
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg0_ADDR \
	CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_ADDR
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg0_MASK \
	0x0000FFFF
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_pcie_remap_wf_rg0_SHFT \
	0

#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_bt_rg0_ADDR \
	CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_ADDR
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_bt_rg0_MASK \
	0xFFFF0000
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_bt_rg0_SHFT \
	16
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_wf_rg2_ADDR \
	CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_ADDR
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_wf_rg2_MASK \
	0x0000FFFF
#define CB_INFRA_MISC0_CBTOP_PCIE_REMAP_WF_BT_pcie_remap_wf_rg2_SHFT \
	0

#ifdef __cplusplus
}
#endif

#endif
