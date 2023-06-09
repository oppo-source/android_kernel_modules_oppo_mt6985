/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 MediaTek Inc.
 */
#ifndef _GPS_MCUSYS_DATA_H_
#define _GPS_MCUSYS_DATA_H_

#include "gps_mcudl_data_intf_type.h"

enum gps_mcusys_mnlbin_event {
	GPS_MCUSYS_MNLBIN_SYS_ON,
	GPS_MCUSYS_MNLBIN_INIT_DONE,
	GPS_MCUSYS_MNLBIN_CTLR_CREATED,

	GPS_MCUSYS_MNLBIN_SYS_RESET_START,
	GPS_MCUSYS_MNLBIN_SYS_RESET_END,

	GPS_MCUSYS_MNLBIN_EVT_NUM
};

enum gps_mcusys_nv_data_id {
	GPS_MCUSYS_NV_DATA_ID_EPO,
	GPS_MCUSYS_NV_DATA_ID_GG_QEPO,
	GPS_MCUSYS_NV_DATA_ID_BD_QEPO,
	GPS_MCUSYS_NV_DATA_ID_GA_QEPO,
	GPS_MCUSYS_NV_DATA_ID_NVFILE,
	GPS_MCUSYS_NV_DATA_ID_CACHE,
	GPS_MCUSYS_NV_DATA_ID_CONFIG,
	GPS_MCUSYS_NV_DATA_ID_CONFIG_WRITE,
	GPS_MCUSYS_NV_DATA_ID_DSPL1,
	GPS_MCUSYS_NV_DATA_ID_DSPL5,
	GPS_MCUSYS_NV_DATA_ID_XEPO,
	GPS_MCUSYS_NV_DATA_ID_QZ_QEPO,
	GPS_MCUSYS_NV_DATA_ID_IR_QEPO,
	GPS_MCUSYS_NV_DATA_ID_KR_QEPO,
	GPS_MCUSYS_NV_DATA_ID_DSPL1_CW,
	GPS_MCUSYS_NV_DATA_ID_DSPL5_CW,
	GPS_MCUSYS_NV_DATA_ID_MPENV,
	GPS_MCUSYS_NV_DATA_ID_MPE_CFG,
	GPS_MCUSYS_NV_DATA_ID_AP_MPE,
	GPS_MCUSYS_NV_DATA_ID_RAW_MEAS,
	GPS_MCUSYS_NV_DATA_ID_RAW_HIGEO,
	GPS_MCUSYS_NV_DATA_NUM
};

enum gps_mcusys_nvlock_event_id {
	GPS_MCUSYS_NVLOCK_HOST_INIT,

	GPS_MCUSYS_NVLOCK_MCU_PRE_ON,
	GPS_MCUSYS_NVLOCK_MCU_POST_ON,
	GPS_MCUSYS_NVLOCK_MCU_PRE_OFF,
	GPS_MCUSYS_NVLOCK_MCU_POST_OFF,

	GPS_MCUSYS_NVLOCK_HOST_TAKE_REQ,
	GPS_MCUSYS_NVLOCK_HOST_GIVE_REQ,

	GPS_MCUSYS_NVLOCK_MCU_TAKE_ACK,
	GPS_MCUSYS_NVLOCK_MCU_GIVE_ACK,
};

enum gps_mcusys_nvdata_event_id {
	GPS_MCUSYS_NVDATA_MCU_OPEN,
	GPS_MCUSYS_NVDATA_MCU_READ,
	GPS_MCUSYS_NVDATA_MCU_WRITE,
	GPS_MCUSYS_NVDATA_MCU_CLOSE,
	GPS_MCUSYS_NVDATA_MCU_DELETE,
};

struct gps_mcusys_nvlock_event {
	enum gps_mcusys_nv_data_id nv_id;
	enum gps_mcusys_nvlock_event_id evt_id;
};

struct gps_mcusys_nvdata_event {
	enum gps_mcusys_nv_data_id nv_id;
	enum gps_mcusys_nvdata_event_id evt_id;
};

enum gps_mcusys_host_status_cmd_id {
	GPS_MCUSYS_HOST_STATUS_POST_ON,
	GPS_MCUSYS_HOST_STATUS_XBITMASK,

	GPS_MCUSYS_HOST_STATUS_NUM
};

struct gps_mcusys_host_status_cmd {
	enum gps_mcusys_host_status_cmd_id cmd_id;

	/* Only valid for GPS_MCUSYS_HOST_STATUS_XSTATUS_BITMASK */
	unsigned int xstatus_bitmask;
};

#endif /* _GPS_MCUSYS_DATA_H_ */

