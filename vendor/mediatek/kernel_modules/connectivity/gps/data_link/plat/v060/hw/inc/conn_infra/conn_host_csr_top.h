/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#ifndef __CONN_HOST_CSR_TOP_REGS_H__
#define __CONN_HOST_CSR_TOP_REGS_H__

#define CONN_HOST_CSR_TOP_BASE                                 0x18060000

#define CONN_HOST_CSR_TOP_GPS_LPCTL_ADDR                       (CONN_HOST_CSR_TOP_BASE + 0x040)
#define CONN_HOST_CSR_TOP_CONN_INFRA_WAKEPU_GPS_ADDR           (CONN_HOST_CSR_TOP_BASE + 0x1AC)
#define CONN_HOST_CSR_TOP_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_ADDR (CONN_HOST_CSR_TOP_BASE + 0x360)
#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_ADDR              (CONN_HOST_CSR_TOP_BASE + 0xA10)

#define CONN_HOST_CSR_TOP_GPS_LPCTL_GPS_AP_HOST_CLR_FW_OWN_HS_PULSE_ADDR \
	CONN_HOST_CSR_TOP_GPS_LPCTL_ADDR
#define CONN_HOST_CSR_TOP_GPS_LPCTL_GPS_AP_HOST_CLR_FW_OWN_HS_PULSE_MASK 0x00000002
#define CONN_HOST_CSR_TOP_GPS_LPCTL_GPS_AP_HOST_CLR_FW_OWN_HS_PULSE_SHFT 1

#define CONN_HOST_CSR_TOP_CONN_INFRA_WAKEPU_GPS_CONN_INFRA_WAKEPU_GPS_ADDR \
	CONN_HOST_CSR_TOP_CONN_INFRA_WAKEPU_GPS_ADDR
#define CONN_HOST_CSR_TOP_CONN_INFRA_WAKEPU_GPS_CONN_INFRA_WAKEPU_GPS_MASK 0x00000001
#define CONN_HOST_CSR_TOP_CONN_INFRA_WAKEPU_GPS_CONN_INFRA_WAKEPU_GPS_SHFT 0

#define CONN_HOST_CSR_TOP_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_ADDR \
	CONN_HOST_CSR_TOP_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_ADDR
#define CONN_HOST_CSR_TOP_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_MASK \
	0x000FFFFF
#define CONN_HOST_CSR_TOP_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_CONN2AP_REMAP_GPS_EMI_BASE_ADDR_SHFT 0

#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_S_ADDR \
	CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_ADDR
#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_S_MASK 0x00040000
#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_S_SHFT 18

#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_ADDR \
	CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_ADDR
#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_MASK 0x00080000
#define CONN_HOST_CSR_TOP_CONNSYS_PWR_STATES_CONNSYS_PWR_STATES_SHFT 19

#endif /* __CONN_HOST_CSR_TOP_REGS_H__*/
