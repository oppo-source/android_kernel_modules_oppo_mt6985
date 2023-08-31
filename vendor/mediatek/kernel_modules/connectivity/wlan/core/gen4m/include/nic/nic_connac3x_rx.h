/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2016 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2016 MediaTek Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

/*! \file   nic_connac3x_rx.h
*    \brief  Functions that provide TX operation in NIC's point of view.
*
*    This file provides TX functions which are responsible for both Hardware and
*    Software Resource Management and keep their Synchronization.
*
*/


#ifndef _NIC_CONNAC3X_RX_H
#define _NIC_CONNAC3X_RX_H

#if (CFG_SUPPORT_CONNAC3X == 1)
/*******************************************************************************
*                         C O M P I L E R   F L A G S
********************************************************************************
*/

/*******************************************************************************
*                    E X T E R N A L   R E F E R E N C E S
********************************************************************************
*/

/*******************************************************************************
*                              C O N S T A N T S
********************************************************************************
*/
#define CONNAC3X_RX_STATUS_PKT_TYPE_SW_BITMAP 0x380F
#define CONNAC3X_RX_STATUS_PKT_TYPE_SW_EVENT  0x3800
#define CONNAC3X_RX_STATUS_PKT_TYPE_SW_FRAME  0x3801

/*------------------------------------------------------------------------------
 * Bit fields for HW_MAC_RX_DESC_T
 *------------------------------------------------------------------------------
*/

/*! MAC CONNAC3X RX DMA Descriptor */
/* DW 0*/
#define CONNAC3X_RX_STATUS_RX_BYTE_COUNT_MASK    BITS(0, 15)
#define CONNAC3X_RX_STATUS_RX_BYTE_COUNT_OFFSET  0
#define CONNAC3X_RX_STATUS_ETH_TYPE_MASK         BITS(16, 22)
#define CONNAC3X_RX_STATUS_ETH_TYPE_OFFSET       16
#define CONNAC3X_RX_STATUS_PKT_TYPE_MASK         BITS(27, 31)
#define CONNAC3X_RX_STATUS_PKT_TYPE_OFFSET       27

/* DW 1 */
#define CONNAC3X_RX_STATUS_MLD_ID_MASK                   BITS(0, 11)
#define CONNAC3X_RX_STATUS_MLD_ID_OFFSET                 0
#define CONNAC3X_RX_STATUS_GROUP_VLD_MASK                BITS(16, 20)
#define CONNAC3X_RX_STATUS_GROUP_VLD_OFFSET              16
#define CONNAC3X_RX_STATUS_KEYID_MASK                    BITS(21, 22)
#define CONNAC3X_RX_STATUS_KEYID_OFFSET                  21
#define CONNAC3X_RX_STATUS_FLAG_CIPHER_MISMATCH          BIT(23)
#define CONNAC3X_RX_STATUS_FLAG_CIPHER_LENGTH_MISMATCH   BIT(24)
#define CONNAC3X_RX_STATUS_FLAG_ICV_ERROR                BIT(25)
#define CONNAC3X_RX_STATUS_FLAG_TKIPMIC_ERROR            BIT(26)
#define CONNAC3X_RX_STATUS_BAND_INDICATOR_MASK           BITS(27, 28)
#define CONNAC3X_RX_STATUS_BAND_INDICATOR_OFFSET         27

#define CONNAC3X_RX_STATUS_FLAG_ERROR_MASK  (CONNAC3X_RX_STATUS_FLAG_ICV_ERROR\
	| CONNAC3X_RX_STATUS_FLAG_CIPHER_LENGTH_MISMATCH)/* No TKIP MIC error */

/* DW 2 */
#define CONNAC3X_RX_STATUS_BSSID_MASK            BITS(0, 5)
#define CONNAC3X_RX_STATUS_BSSID_OFFSET          0
#define CONNAC3X_RX_STATUS_FLAG_HEADER_TRAN      BIT(7)
#define CONNAC3X_RX_STATUS_HEADER_LEN_MASK       BITS(8, 12)
#define CONNAC3X_RX_STATUS_HEADER_LEN_OFFSET     8
#define CONNAC3X_RX_STATUS_HEADER_OFFSET_MASK    BITS(13, 15)
#define CONNAC3X_RX_STATUS_HEADER_OFFSET_OFFSET  13
#define CONNAC3X_RX_STATUS_SEC_MASK              BITS(16, 20)
#define CONNAC3X_RX_STATUS_SEC_OFFSET            16
#define CONNAC3X_RX_STATUS_FLAG_SW_BIT           BIT(22)
#define CONNAC3X_RX_STATUS_FLAG_DE_AMSDU_FAIL    BIT(23)
#define CONNAC3X_RX_STATUS_FLAG_EXCEED_LEN       BIT(24)
#define CONNAC3X_RX_STATUS_FLAG_TRANS_FAIL       BIT(25)
#define CONNAC3X_RX_STATUS_FLAG_INTF             BIT(26)
#define CONNAC3X_RX_STATUS_FLAG_FRAG             BIT(27)
#define CONNAC3X_RX_STATUS_FLAG_NULL             BIT(28)
#define CONNAC3X_RX_STATUS_FLAG_NDATA            BIT(29)
#define CONNAC3X_RX_STATUS_FLAG_NAMP             BIT(30)
#define CONNAC3X_RX_STATUS_FLAG_BF_RPT           BIT(31)

/* DW 3 */
#define CONNAC3X_RX_STATUS_RXV_SEQ_NO_MASK       BITS(0, 7)
#define CONNAC3X_RX_STATUS_RXV_SEQ_NO_OFFSET     0
#define CONNAC3X_RX_STATUS_CH_FREQ_MASK          BITS(8, 15)
#define CONNAC3X_RX_STATUS_CH_FREQ_OFFSET        8
#define CONNAC3X_RX_STATUS_A1_TYPE_MASK          BITS(16, 17)
#define CONNAC3X_RX_STATUS_A1_TYPE_OFFSET        16
#define CONNAC3X_RX_STATUS_UC2ME                 BIT(16)
#define CONNAC3X_RX_STATUS_MC_FRAME              BIT(17)
#define CONNAC3X_RX_STATUS_BC_FRAME              BITS(16, 17)

#define CONNAC3X_RX_STATUS_FLAG_HTC              BIT(18)
#define CONNAC3X_RX_STATUS_FLAG_TCL              BIT(19)
#define CONNAC3X_RX_STATUS_FLAG_BBM              BIT(20)
#define CONNAC3X_RX_STATUS_FLAG_BU               BIT(21)
#define CONNAC3X_RX_STATUS_DW3_HW_INFO_MASK      BITS(22, 31)
#define CONNAC3X_RX_STATUS_DW3_HW_INFO_OFFSET    22
#define CONNAC3X_RX_STATUS_FLAG_FCS_ERROR        BIT(24)

/* DW 4 */
#define CONNAC3X_RX_STATUS_PF_MASK               BITS(0, 1)
#define CONNAC3X_RX_STATUS_PF_OFFSET             0
#define CONNAC3X_RX_STATUS_MAC_MASK              BIT(2)
#define CONNAC3X_RX_STATUS_MAC_OFFSET            2
#define CONNAC3X_RX_STATUS_TID_MASK              BITS(3, 6)
#define CONNAC3X_RX_STATUS_TID_OFFSET            3
#define CONNAC3X_RX_STATUS_CLASSIFY_MASK         BITS(28, 30)
#define CONNAC3X_RX_STATUS_CLASSIFY_OFFSET       28


/* DW 5 */
#define CONNAC3X_RX_STATUS_CHECKSUM_MASK         BITS(0, 10)
#define CONNAC3X_RX_STATUS_CHECKSUM_OFFSET       0

/* DW 7 */
#define CONNAC3X_RX_STATUS_OFLD_MASK             BITS(21, 22)
#define CONNAC3X_RX_STATUS_OFLD_OFFSET           21
#define CONNAC3X_RX_STATUS_PF_STS_MASK           BITS(30, 31)
#define CONNAC3X_RX_STATUS_PF_STS_OFFSET         30

/*
 *   GROUP_VLD: RFB Group valid indicators
 *   Bit[0] indicates GROUP1 (DW10~DW13)
 *   Bit[1] indicates GROUP2 (DW14~DW15)
 *   Bit[2] indicates GROUP3 (DW16~DW17)
 *   Bit[3] indicates GROUP4 (DW6~DW9)
 *   Bit[4] indicates GROUP5 (DW18~DW33)
 */
#define CONNAC3X_RX_STATUS_GROUP1_VALID    BIT(0)
#define CONNAC3X_RX_STATUS_GROUP2_VALID    BIT(1)
#define CONNAC3X_RX_STATUS_GROUP3_VALID    BIT(2)
#define CONNAC3X_RX_STATUS_GROUP4_VALID    BIT(3)
#define CONNAC3X_RX_STATUS_GROUP5_VALID    BIT(4)

#define CONNAC3X_RX_STATUS_FIXED_LEN       24

/* P-RXVector, 1st Cycle */
#define CONNAC3X_RX_P_RXV_RX_RATE_MASK         BITS(0, 6)
#define CONNAC3X_RX_P_RXV_RX_RATE_OFFSET       0
#define CONNAC3X_RX_P_RXV_NSTS_MASK            BITS(7, 10)
#define CONNAC3X_RX_P_RXV_NSTS_OFFSET          7
#define CONNAC3X_RX_P_RXV_BEAMFORMED_MASK      BIT(11)
#define CONNAC3X_RX_P_RXV_BEAMFORMED_OFFSET    11
#define CONNAC3X_RX_P_RXV_LDPC_MASK            BIT(12)
#define CONNAC3X_RX_P_RXV_LDPC_OFFSET          12
#define CONNAC3X_RX_P_RXV_RU_ALLOC_MASK        BITS(22, 30)
#define CONNAC3X_RX_P_RXV_RU_ALLOC_OFFSET      22

/* C-RXC Vector, 1st Cycle */
#define CONNAC3X_RX_C_RXV_STBC_MASK            BITS(0, 1)
#define CONNAC3X_RX_C_RXV_STBC_OFFSET          0
#define CONNAC3X_RX_C_RXV_NESS_MASK            BITS(2, 3)
#define CONNAC3X_RX_C_RXV_NESS_OFFSET          2
#define CONNAC3X_RX_C_RXV_RX_MODE_MASK         BITS(4, 7)
#define CONNAC3X_RX_C_RXV_RX_MODE_OFFSET       4
#define CONNAC3X_RX_C_RXV_FR_MODE_MASK         BITS(11, 13)
#define CONNAC3X_RX_C_RXV_FR_MODE_OFFSET       11
#define CONNAC3X_RX_C_RXV_TXOP_PS_NOT_ALLOWED_MASK     BIT(14)
#define CONNAC3X_RX_C_RXV_TXOP_PS_NOT_ALLOWED_OFFSET   14
#define CONNAC3X_RX_C_RXV_SHORT_GI_MASK        BITS(16, 17)
#define CONNAC3X_RX_C_RXV_SHORT_GI_OFFSET      16
#define CONNAC3X_RX_C_RXV_NUM_USER_MASK        BITS(20, 26)
#define CONNAC3X_RX_C_RXV_NUM_USER_OFFSET      20
#define CONNAC3X_RX_C_RXV_LTF_MASK             BITS(27, 28)
#define CONNAC3X_RX_C_RXV_LTF_OFFSET           27
#define CONNAC3X_RX_C_RXV_LDPC_EXTRA_OFDM_SYM_MASK     BIT(30)
#define CONNAC3X_RX_C_RXV_LDPC_EXTRA_OFDM_SYM_OFFSET   30

#define CONNAC3X_RX_C_RXV_PE_DIS_AMB_MASK      BIT(1)
#define CONNAC3X_RX_C_RXV_PE_DIS_AMB_OFFSET    1
#define CONNAC3X_RX_C_RXV_UL_DL_MASK           BIT(2)
#define CONNAC3X_RX_C_RXV_UL_DL_OFFSET         2

/* C-RXC Vector, 2nd Cycle */
#define CONNAC3X_RX_C_RXV_GROUP_ID_MASK        BITS(22, 27)
#define CONNAC3X_RX_C_RXV_GROUP_ID_OFFSET      22
#define CONNAC3X_RX_C_RXV_NUM_RX_MASK          BITS(28, 30)
#define CONNAC3X_RX_C_RXV_NUM_RX_OFFSET		   28

/* C-RXC Vector, 3rd Cycle */
#define CONNAC3X_RX_C_RXV_PART_AID_MASK        BITS(17, 27)
#define CONNAC3X_RX_C_RXV_PART_AID_OFFSET      17
#define CONNAC3X_RX_C_RXV_BEAM_CHANGE_MASK     BIT(29)
#define CONNAC3X_RX_C_RXV_BEAM_CHANGE_OFFSET   29
#define CONNAC3X_RX_C_RXV_DCM_MASK             BIT(31)
#define CONNAC3X_RX_C_RXV_DCM_OFFSET           31

#define CONNAC3X_RX_C_RXV_DOPPLER_MASK         BIT(0)
#define CONNAC3X_RX_C_RXV_DOPPLER_OFFSET       0
#define CONNAC3X_RX_C_RXV_BSS_COLOR_MASK       BITS(10, 15)
#define CONNAC3X_RX_C_RXV_BSS_COLOR_OFFSET     10
#define CONNAC3X_RX_C_RXV_TXOP_MASK            BITS(17, 23)
#define CONNAC3X_RX_C_RXV_TXOP_OFFSET          17

/* C-RXC Vector, 4th Cycle */
#define CONNAC3X_RX_C_RXV_RCPI0_MASK           BITS(0, 7)
#define CONNAC3X_RX_C_RXV_RCPI0_OFFSET         0
#define CONNAC3X_RX_C_RXV_RCPI1_MASK           BITS(8, 15)
#define CONNAC3X_RX_C_RXV_RCPI1_OFFSET         8
#define CONNAC3X_RX_C_RXV_RCPI2_MASK           BITS(16, 23)
#define CONNAC3X_RX_C_RXV_RCPI2_OFFSET         16
#define CONNAC3X_RX_C_RXV_RCPI3_MASK           BITS(24, 31)
#define CONNAC3X_RX_C_RXV_RCPI3_OFFSET         24

/* C-RXC Vector, 5th Cycle */
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE1_MASK      BITS(8, 11)
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE1_OFFSET    8
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE2_MASK      BITS(12, 15)
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE2_OFFSET    12
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE3_MASK      BITS(16, 19)
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE3_OFFSET    16
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE4_MASK      BITS(20, 23)
#define CONNAC3X_RX_C_RXV_SPATIAL_REUSE4_OFFSET    20

/* C-RXC Vector, 7th Cycle */
#define CONNAC3X_RX_C_RXV_SIGB_RU0_MASK        BITS(0, 8)
#define CONNAC3X_RX_C_RXV_SIGB_RU0_OFFSET      0
#define CONNAC3X_RX_C_RXV_SIGB_RU1_MASK        BITS(9, 17)
#define CONNAC3X_RX_C_RXV_SIGB_RU1_OFFSET      9
#define CONNAC3X_RX_C_RXV_SIGB_RU2_MASK        BITS(18, 26)
#define CONNAC3X_RX_C_RXV_SIGB_RU2_OFFSET      18
#define CONNAC3X_RX_C_RXV_SIGB_RU3_MASK        BITS(27, 31)
#define CONNAC3X_RX_C_RXV_SIGB_RU3_OFFSET      27

#define CONNAC3X_RX_C_RXV_SIGB_RU3_1_MASK      BITS(0, 3)
#define CONNAC3X_RX_C_RXV_SIGB_RU3_1_OFFSET    5

/*******************************************************************************
*                             D A T A   T Y P E S
********************************************************************************
*/

/*! A data structure which is identical with MAC RX DMA Descriptor */
struct HW_MAC_CONNAC3X_RX_DESC {
	uint32_t u4DW0;
	uint32_t u4DW1;
	uint32_t u4DW2;
	uint32_t u4DW3;
	uint32_t u4DW4;
	uint32_t u4DW5;
	uint32_t u4DW6;
	uint32_t u4DW7;
};

/*******************************************************************************
*                            P U B L I C   D A T A
********************************************************************************
*/

/*******************************************************************************
*                           P R I V A T E   D A T A
********************************************************************************
*/

/*******************************************************************************
*                                 M A C R O S
********************************************************************************
*/

#define RX_DESC_GET_FIELD(_rHwMacTxDescField, _mask, _offset) \
	(((_rHwMacTxDescField) & (_mask)) >> (_offset))

/*------------------------------------------------------------------------------
 * MACRO for HW_MAC_RX_DESC_T
 *------------------------------------------------------------------------------
*/

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_RX_BYTE_CNT(_prHwMacRxDesc) \
	RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW0, \
		CONNAC3X_RX_STATUS_RX_BYTE_COUNT_MASK, \
		CONNAC3X_RX_STATUS_RX_BYTE_COUNT_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_ETH_TYPE_OFFSET(_prHwMacRxDesc)	\
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW0, \
CONNAC3X_RX_STATUS_ETH_TYPE_MASK, CONNAC3X_RX_STATUS_ETH_TYPE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_PKT_TYPE(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW0, \
CONNAC3X_RX_STATUS_PKT_TYPE_MASK, CONNAC3X_RX_STATUS_PKT_TYPE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_MLD_ID(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW1, \
CONNAC3X_RX_STATUS_MLD_ID_MASK, CONNAC3X_RX_STATUS_MLD_ID_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_GROUP_VLD(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW1, \
CONNAC3X_RX_STATUS_GROUP_VLD_MASK, CONNAC3X_RX_STATUS_GROUP_VLD_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_SEC_MODE(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW2, \
CONNAC3X_RX_STATUS_SEC_MASK, CONNAC3X_RX_STATUS_SEC_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_KID(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW1, \
CONNAC3X_RX_STATUS_KEYID_MASK, CONNAC3X_RX_STATUS_KEYID_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_CIPHER_MISMATCH(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW1 & CONNAC3X_RX_STATUS_FLAG_CIPHER_MISMATCH) \
	? TRUE : FALSE)
#define HAL_MAC_CONNAC3X_RX_STATUS_IS_CLM_ERROR(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW1 & CONNAC3X_RX_STATUS_FLAG_CIPHER_LENGTH_MISMATCH) \
	? TRUE : FALSE)
#define HAL_MAC_CONNAC3X_RX_STATUS_IS_ICV_ERROR(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW1 & CONNAC3X_RX_STATUS_FLAG_ICV_ERROR)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_TKIP_MIC_ERROR(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW1 & CONNAC3X_RX_STATUS_FLAG_TKIPMIC_ERROR)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_FCS_ERROR(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW3 & CONNAC3X_RX_STATUS_FLAG_FCS_ERROR)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_ERROR(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW1 & CONNAC3X_RX_STATUS_FLAG_ERROR_MASK)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_BAND_IDX(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW1, \
CONNAC3X_RX_STATUS_BAND_INDICATOR_MASK, \
CONNAC3X_RX_STATUS_BAND_INDICATOR_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_HEADER_OFFSET(_prHwMacRxDesc) \
((RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW2, \
CONNAC3X_RX_STATUS_HEADER_OFFSET_MASK, \
CONNAC3X_RX_STATUS_HEADER_OFFSET_OFFSET)) << 1)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_HEADER_LEN(_prHwMacRxDesc)	\
(RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW2, \
CONNAC3X_RX_STATUS_HEADER_LEN_MASK, CONNAC3X_RX_STATUS_HEADER_LEN_OFFSET) << 1)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_HEADER_TRAN(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_HEADER_TRAN)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_DAF(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_DE_AMSDU_FAIL)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_FRAG(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_FRAG)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_NDATA(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_NDATA)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_NAMP(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_NAMP)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_SW_DEFINE_RX_CLASSERR(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_SW_BIT)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_LLC_MIS(_prHwMacRxDesc) \
(((_prHwMacRxDesc)->u4DW2 & CONNAC3X_RX_STATUS_FLAG_TRANS_FAIL)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_TID(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW4, \
CONNAC3X_RX_STATUS_TID_MASK, CONNAC3X_RX_STATUS_TID_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_CLASSIFY(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW4, \
CONNAC3X_RX_STATUS_CLASSIFY_MASK, CONNAC3X_RX_STATUS_CLASSIFY_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_RXV_SEQ_NO(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW3, \
CONNAC3X_RX_STATUS_RXV_SEQ_NO_MASK, CONNAC3X_RX_STATUS_RXV_SEQ_NO_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_UC2ME(_prHwMacRxDesc) \
	(((_prHwMacRxDesc)->u4DW3 & CONNAC3X_RX_STATUS_BC_FRAME) \
		== CONNAC3X_RX_STATUS_UC2ME)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_MC(_prHwMacRxDesc) \
	(((_prHwMacRxDesc)->u4DW3 & CONNAC3X_RX_STATUS_BC_FRAME) \
		== CONNAC3X_RX_STATUS_MC_FRAME)

#define HAL_MAC_CONNAC3X_RX_STATUS_IS_BC(_prHwMacRxDesc) \
	(((_prHwMacRxDesc)->u4DW3 & CONNAC3X_RX_STATUS_BC_FRAME) \
		== CONNAC3X_RX_STATUS_BC_FRAME)

#define HAL_RX_CONNAC3X_STATUS_GET_PAYLOAD_FORMAT(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW4, \
CONNAC3X_RX_STATUS_PF_MASK, CONNAC3X_RX_STATUS_PF_OFFSET)

#if (CFG_SUPPORT_WIFI_6G == 1)
#define HAL_MAC_CONNAC3X_RX_STATUS_GET_RF_BAND(_prHwMacRxDesc) \
(((RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW3, \
CONNAC3X_RX_STATUS_CH_FREQ_MASK, CONNAC3X_RX_STATUS_CH_FREQ_OFFSET)) \
<= HW_CHNL_NUM_MAX_2G4) ? BAND_2G4 : \
((RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW3, \
CONNAC3X_RX_STATUS_CH_FREQ_MASK, CONNAC3X_RX_STATUS_CH_FREQ_OFFSET)) \
> HW_CHNL_NUM_MAX_5G) ? BAND_6G : \
BAND_5G)
#else
#define HAL_MAC_CONNAC3X_RX_STATUS_GET_RF_BAND(_prHwMacRxDesc) \
(((RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW3, \
CONNAC3X_RX_STATUS_CH_FREQ_MASK, CONNAC3X_RX_STATUS_CH_FREQ_OFFSET)) \
<= HW_CHNL_NUM_MAX_2G4) ? BAND_2G4 : BAND_5G)
#endif

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_CHNL_NUM(_prHwMacRxDesc) \
(RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW3, \
CONNAC3X_RX_STATUS_CH_FREQ_MASK, CONNAC3X_RX_STATUS_CH_FREQ_OFFSET))

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_TCL(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW3 & CONNAC3X_RX_STATUS_FLAG_TCL)?TRUE:FALSE)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_PAYLOAD_FORMAT(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW4, \
CONNAC3X_RX_STATUS_PF_MASK, CONNAC3X_RX_STATUS_PF_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_CHECKSUM(_prHwMacRxDesc) \
RX_DESC_GET_FIELD((_prHwMacRxDesc)->u4DW5, \
CONNAC3X_RX_STATUS_CHECKSUM_MASK, \
CONNAC3X_RX_STATUS_CHECKSUM_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_OFLD(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW7 & CONNAC3X_RX_STATUS_OFLD_MASK) >> \
CONNAC3X_RX_STATUS_OFLD_OFFSET)

#define HAL_MAC_CONNAC3X_RX_STATUS_GET_PF_STS(_prHwMacRxDesc)	\
(((_prHwMacRxDesc)->u4DW7 & CONNAC3X_RX_STATUS_PF_STS_MASK) >> \
CONNAC3X_RX_STATUS_PF_STS_OFFSET)

/* Group3 P-B-0 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_RX_RATE(_prHwMacRxStsGroup3)	\
(((_prHwMacRxStsGroup3)->u4RxVector[0] & CONNAC3X_RX_P_RXV_RX_RATE_MASK) >> \
	CONNAC3X_RX_P_RXV_RX_RATE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_NSTS(_prHwMacRxStsGroup3)	\
(((_prHwMacRxStsGroup3)->u4RxVector[0] & CONNAC3X_RX_P_RXV_NSTS_MASK) >> \
	CONNAC3X_RX_P_RXV_NSTS_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_BEAMFORMED(_prHwMacRxStsGroup3)	\
(((_prHwMacRxStsGroup3)->u4RxVector[0] & CONNAC3X_RX_P_RXV_BEAMFORMED_MASK) >> \
	CONNAC3X_RX_P_RXV_BEAMFORMED_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_LDPC(_prHwMacRxStsGroup3)	\
(((_prHwMacRxStsGroup3)->u4RxVector[0] & CONNAC3X_RX_P_RXV_LDPC_MASK) >> \
	CONNAC3X_RX_P_RXV_LDPC_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_RU_ALLOC(_prHwMacRxStsGroup3)	\
(((_prHwMacRxStsGroup3)->u4RxVector[0] & CONNAC3X_RX_P_RXV_RU_ALLOC_MASK) >> \
	CONNAC3X_RX_P_RXV_RU_ALLOC_OFFSET)

/* Group5 C-B-0 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_STBC(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_STBC_MASK) >> \
	CONNAC3X_RX_C_RXV_STBC_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_NESS(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_NESS_MASK) >> \
	CONNAC3X_RX_C_RXV_NESS_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_RX_MODE(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_RX_MODE_MASK) >> \
	CONNAC3X_RX_C_RXV_RX_MODE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_FR_MODE(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_FR_MODE_MASK) >> \
	CONNAC3X_RX_C_RXV_FR_MODE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_TXOP_PS_NOT_ALLOWED(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & \
	CONNAC3X_RX_C_RXV_TXOP_PS_NOT_ALLOWED_MASK) >> \
	CONNAC3X_RX_C_RXV_TXOP_PS_NOT_ALLOWED_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_SHORT_GI(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_SHORT_GI_MASK) >> \
	CONNAC3X_RX_C_RXV_SHORT_GI_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_LTF(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_LTF_MASK) >> \
	CONNAC3X_RX_C_RXV_LTF_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_LDPC_EXTRA_OFDM_SYM(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & \
	CONNAC3X_RX_C_RXV_LDPC_EXTRA_OFDM_SYM_MASK) >> \
	CONNAC3X_RX_C_RXV_LDPC_EXTRA_OFDM_SYM_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_NUM_USER(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[0] & CONNAC3X_RX_C_RXV_NUM_USER_MASK) >> \
	CONNAC3X_RX_C_RXV_NUM_USER_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_PE_DIS_AMB(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[1] & CONNAC3X_RX_C_RXV_PE_DIS_AMB_MASK) >> \
	CONNAC3X_RX_C_RXV_PE_DIS_AMB_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_UL_DL(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[1] & CONNAC3X_RX_C_RXV_UL_DL_MASK) >> \
	CONNAC3X_RX_C_RXV_UL_DL_OFFSET)

/* Group5 C-B-1 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_GROUP_ID(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[2] & CONNAC3X_RX_C_RXV_GROUP_ID_MASK) >> \
	CONNAC3X_RX_C_RXV_GROUP_ID_OFFSET)

/* Group5 C-B-2 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_PART_AID(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[4] & CONNAC3X_RX_C_RXV_PART_AID_MASK) >> \
	CONNAC3X_RX_C_RXV_PART_AID_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_BEAM_CHANGE(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[4] & CONNAC3X_RX_C_RXV_BEAM_CHANGE_MASK) >> \
	CONNAC3X_RX_C_RXV_BEAM_CHANGE_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_DCM(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[4] & CONNAC3X_RX_C_RXV_DCM_MASK) >> \
	CONNAC3X_RX_C_RXV_DCM_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_DOPPLER(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[5] & CONNAC3X_RX_C_RXV_DOPPLER_MASK) >> \
	CONNAC3X_RX_C_RXV_DOPPLER_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_BSS_COLOR(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[5] & CONNAC3X_RX_C_RXV_BSS_COLOR_MASK) >> \
	CONNAC3X_RX_C_RXV_BSS_COLOR_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_TXOP(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[5] & CONNAC3X_RX_C_RXV_TXOP_MASK) >> \
	CONNAC3X_RX_C_RXV_TXOP_OFFSET)

/* Group5 C-B-3 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_RCPI0(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[6] & CONNAC3X_RX_C_RXV_RCPI0_MASK) >> \
	CONNAC3X_RX_C_RXV_RCPI0_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_RCPI1(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[6] & CONNAC3X_RX_C_RXV_RCPI1_MASK) >> \
	CONNAC3X_RX_C_RXV_RCPI1_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_RCPI2(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[6] & CONNAC3X_RX_C_RXV_RCPI2_MASK) >> \
	CONNAC3X_RX_C_RXV_RCPI2_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_RCPI3(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[6] & CONNAC3X_RX_C_RXV_RCPI3_MASK) >> \
	CONNAC3X_RX_C_RXV_RCPI3_OFFSET)

/* Group5 C-B-4 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_SPATIAL_REUSE1(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[9] & \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE1_MASK) >> \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE1_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_SPATIAL_REUSE2(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[9] & \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE2_MASK) >> \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE2_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_SPATIAL_REUSE3(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[9] & \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE3_MASK) >> \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE3_OFFSET)
#define HAL_MAC_CONNAC3X_RX_VT_GET_SPATIAL_REUSE4(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[9] & \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE4_MASK) >> \
	CONNAC3X_RX_C_RXV_SPATIAL_REUSE4_OFFSET)

/* Group5 C-B-6 */
#define HAL_MAC_CONNAC3X_RX_VT_GET_SIGB_RU0(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[12] & CONNAC3X_RX_C_RXV_SIGB_RU0_MASK) >> \
	CONNAC3X_RX_C_RXV_SIGB_RU0_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_SIGB_RU1(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[12] & CONNAC3X_RX_C_RXV_SIGB_RU1_MASK) >> \
	CONNAC3X_RX_C_RXV_SIGB_RU1_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_SIGB_RU2(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[12] & CONNAC3X_RX_C_RXV_SIGB_RU2_MASK) >> \
	CONNAC3X_RX_C_RXV_SIGB_RU2_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_SIGB_RU3(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[12] & CONNAC3X_RX_C_RXV_SIGB_RU3_MASK) >> \
	CONNAC3X_RX_C_RXV_SIGB_RU3_OFFSET)

#define HAL_MAC_CONNAC3X_RX_VT_GET_SIGB_RU3_1(_prHwMacRxStsGroup5)	\
(((_prHwMacRxStsGroup5)->u4RxVector[13] & CONNAC3X_RX_C_RXV_SIGB_RU3_1_MASK) << \
	CONNAC3X_RX_C_RXV_SIGB_RU3_1_OFFSET)

/*******************************************************************************
*                  F U N C T I O N   D E C L A R A T I O N S
********************************************************************************
*/


/*******************************************************************************
*                              F U N C T I O N S
********************************************************************************
*/

#endif /* CFG_SUPPORT_CONNAC3X == 1 */
#endif /* _NIC_CONNAC3X_RX_H */

