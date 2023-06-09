/* SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause */
/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2019 MediaTek Inc.
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
 * Copyright(C) 2019 MediaTek Inc.
 * All rights reserved.
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
/*
 * This file is part of the libpayload project.
 *
 * Copyright (C) 2008-2010 coresystems GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 */

#ifndef __LD_USBBT_H__
#define __LD_USBBT_H__
#include <common.h>
#include <malloc.h>
#include <usb.h>
#include <MsTypes.h>

#define MTKBT_CTRL_TX_EP 0
#define MTKBT_CTRL_RX_EP 1
#define MTKBT_INTR_EP 2
#define MTKBT_BULK_TX_EP 3
#define MTKBT_BULK_RX_EP 4

#define USB_INTR_MSG_TIMO 2000

#define MTK_GFP_ATOMIC 1

#define CRC_CHECK 0
#define BT_USB_PORT "bt_usb_port"

#define BTLDER				"[BT-LOADER] "
#define USB_TYPE_STANDARD	(0x00 << 5)
#define USB_TYPE_CLASS		(0x01 << 5)
#define USB_TYPE_VENDOR		(0x02 << 5)
#define USB_TYPE_RESERVED	(0x03 << 5)


#define usb_debug(fmt,...) printf("%s: "fmt, __func__, ##__VA_ARGS__)
#define usb_debug_raw(p, l, fmt, ...) \
	do { \
		int raw_count = 0; \
		const unsigned char *ptr = p; \
		printf("%s: "fmt, __func__, ##__VA_ARGS__); \
		for (raw_count = 0; raw_count < l; ++raw_count) \
			printf(" %02X", ptr[raw_count]); \
			printf("\n"); \
	} while (0)

#define os_kmalloc(size,flags) malloc(size)
#define os_kfree(ptr) free(ptr)

#define MTK_UDELAY(x)  udelay(x)
#define MTK_MDELAY(x)  mdelay(x)


//#define btusbdev_t struct usb_interface
#define btusbdev_t struct usb_device

#undef NULL
#define NULL ((void *)0)
#define s32 signed int
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef unsigned int UINT32;
typedef signed int INT32;
typedef unsigned char UINT8;
typedef unsigned long ULONG;
typedef unsigned char BOOL;

typedef struct __USBBT_DEVICE__ mtkbt_dev_t;

typedef struct {
	int (*usb_bulk_msg) (mtkbt_dev_t *dev, u32 epType, u8 *data, int size, int* realsize, int timeout);
	int (*usb_control_msg) (mtkbt_dev_t *dev, u32 epType, u8 request, u8 requesttype, u16 value, u16 index,
			u8 *data, int data_length, int timeout);
	int (*usb_interrupt_msg)(mtkbt_dev_t *dev, u32 epType, u8 *data, int size, int* realsize, int timeout);
} HC_IF;

struct __USBBT_DEVICE__
{
	void *priv_data;
	btusbdev_t* intf;
	struct usb_device *udev;
	struct usb_endpoint_descriptor *intr_ep;
	struct usb_endpoint_descriptor *bulk_tx_ep;
	struct usb_endpoint_descriptor *bulk_rx_ep;
	struct usb_endpoint_descriptor *isoc_tx_ep;
	struct usb_endpoint_descriptor *isoc_rx_ep;
	HC_IF *hci_if;
	int  (*connect)(btusbdev_t *dev, int flag);
	void (*disconnect)(btusbdev_t *dev);
	int  (*SetWoble)(btusbdev_t *dev);
	u32 chipid;
};//mtkbt_dev_t;

#define BT_INST(dev) (dev)

u8 LDbtusb_getWoBTW(void);
int Ldbtusb_connect (btusbdev_t *dev, int falg);
VOID *os_memcpy(VOID *dst, const VOID *src, UINT32 len);
VOID *os_memmove(VOID *dest, const void *src,UINT32 len);
VOID *os_memset(VOID *s, int c, size_t n);
VOID *os_kzalloc(size_t size, unsigned int flags);

void LD_load_code_from_bin(unsigned char **image, char *bin_name, char *path, mtkbt_dev_t *dev,u32 *code_len);

int do_setMtkBT(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[]);
int do_getMtkBTWakeT(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[]);

#endif
