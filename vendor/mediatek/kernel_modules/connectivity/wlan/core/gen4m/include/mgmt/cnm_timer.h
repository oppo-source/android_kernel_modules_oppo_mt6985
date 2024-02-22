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
/*
 * Id: //Department/DaVinci/BRANCHES/MT6620_WIFI_DRIVER_V2_3
 *     /include/mgmt/cnm_timer.h#1
 */

/*! \file   cnm_timer.h
 *    \brief  Declaration of timer obj and related timer macro for setup time
 *    out event.
 *
 *    In this file we declare the timer object and provide several macro for
 *    Protocol functional blocks to setup their own time out event.
 */


#ifndef _CNM_TIMER_H
#define _CNM_TIMER_H

/*******************************************************************************
 *                         C O M P I L E R   F L A G S
 *******************************************************************************
 */

/*******************************************************************************
 *                    E X T E R N A L   R E F E R E N C E S
 *******************************************************************************
 */

/*******************************************************************************
 *                              C O N S T A N T S
 *******************************************************************************
 */
#undef MSEC_PER_SEC
#define MSEC_PER_SEC			1000
#undef USEC_PER_MSEC
#define USEC_PER_MSEC			1000
#undef NSEC_PER_USEC
#define NSEC_PER_USEC			1000
#undef USEC_PER_SEC
#define USEC_PER_SEC			1000000
#undef NSEC_PER_SEC
#define NSEC_PER_SEC			1000000000

#define USEC_PER_TU			1024	/* microsecond */

#define MSEC_PER_MIN			(60 * MSEC_PER_SEC)

#define SEC_PER_HOUR			(3600)
#define HOUR_MAX			(24)
#define SEC_PER_MINUTE			(60)
#define MINUTE_MAX			(60)

#define MGMT_MAX_TIMEOUT_INTERVAL	((uint32_t)0x7fffffff)

#define WAKE_LOCK_MAX_TIME		5	/* Unit: sec */

/* If WAKE_LOCK_MAX_TIME is too large, the whole system may always keep awake
 * because of periodic timer of OBSS scanning
 */
#if (WAKE_LOCK_MAX_TIME >= OBSS_SCAN_MIN_INTERVAL)
#error WAKE_LOCK_MAX_TIME is too large
#endif

enum ENUM_TIMER_WAKELOCK_TYPE_T {
	TIMER_WAKELOCK_AUTO,
	TIMER_WAKELOCK_NONE,
	TIMER_WAKELOCK_REQUEST,
	TIMER_WAKELOCK_NUM
};

/*******************************************************************************
 *                             D A T A   T Y P E S
 *******************************************************************************
 */
typedef void(*PFN_MGMT_TIMEOUT_FUNC) (struct ADAPTER *, uintptr_t);

struct TIMER {
	struct LINK_ENTRY rLinkEntry;
	OS_SYSTIME rExpiredSysTime;
	uint16_t u2Minutes;
	uint16_t u2Reserved;
	uintptr_t ulDataPtr;
	PFN_MGMT_TIMEOUT_FUNC pfMgmtTimeOutFunc;
	enum ENUM_TIMER_WAKELOCK_TYPE_T eType;
};

/*******************************************************************************
 *                            P U B L I C   D A T A
 *******************************************************************************
 */

/*******************************************************************************
 *                           P R I V A T E   D A T A
 *******************************************************************************
 */

/*******************************************************************************
 *                                 M A C R O S
 *******************************************************************************
 */
/* Check if time "a" is before time "b" */
/* In 32-bit variable, 0x00000001~0x7fffffff -> positive number,
 *                     0x80000000~0xffffffff -> negative number
 */
#define TIME_BEFORE_64bit(a, b)		(a < b)

#define TIME_BEFORE(a, b) \
	((uint32_t)((uint32_t)(a) - (uint32_t)(b)) > 0x7fffffff)

/* #define TIME_BEFORE(a,b) ((int32_t)((int32_t)(b) - (int32_t)(a)) > 0)
 * may cause UNexpect result between Free build and Check build for WinCE
 */

#define TIME_AFTER(a, b)		TIME_BEFORE(b, a)

#define SYSTIME_TO_SEC(_systime)	((_systime) / KAL_HZ)
#define SEC_TO_SYSTIME(_sec)		((_sec) * KAL_HZ)

/* The macros to convert second & hours/minutes */
#define SEC_TO_TIME_HOUR(_sec) \
	(((uint32_t)(_sec) / SEC_PER_HOUR) % HOUR_MAX)
#define SEC_TO_TIME_MINUTE(_sec) \
	(((uint32_t)(_sec) / SEC_PER_MINUTE) % MINUTE_MAX)
#define SEC_TO_TIME_SECOND(_sec)	((uint32_t)(_sec) % SEC_PER_MINUTE)

/* The macros to convert second & millisecond */
#define MSEC_TO_SEC(_msec)		((_msec) / MSEC_PER_SEC)
#define NSEC_TO_USEC(_nsec)		((_nsec) / NSEC_PER_USEC)
#define SEC_TO_MSEC(_sec)		((uint32_t)(_sec) * MSEC_PER_SEC)
#define SEC_TO_USEC(_sec)		((uint32_t)(_sec) * USEC_PER_SEC)
#define SEC_TO_NSEC(_sec)		((uint64_t)(_sec) * NSEC_PER_SEC)
#define SEC_TO_TU(_sec) \
	((uint32_t)(_sec) * USEC_PER_SEC / USEC_PER_TU)

/* The macros to convert millisecond & microsecond */
#define USEC_TO_MSEC(_usec)		((_usec) / USEC_PER_MSEC)
#define MSEC_TO_USEC(_msec)		((uint32_t)(_msec) * USEC_PER_MSEC)

/* The macros to convert TU & microsecond, TU & millisecond */
#define TU_TO_USEC(_tu)			((_tu) * USEC_PER_TU)
#define TU_TO_MSEC(_tu)			USEC_TO_MSEC(TU_TO_USEC(_tu))

/* The macros to convert TU & & OS system time, round up by 0.5 */
#define TU_TO_SYSTIME(_tu)		MSEC_TO_SYSTIME(TU_TO_MSEC(_tu))
#define SYSTIME_TO_TU(_systime) \
	((SYSTIME_TO_USEC(_systime) + ((USEC_PER_TU / 2) - 1)) / USEC_PER_TU)

/* The macros to convert OS system time & microsecond */
#define SYSTIME_TO_USEC(_systime)	(((_systime) * USEC_PER_SEC) / KAL_HZ)

/* The macro to get the current OS system time */
#define GET_CURRENT_SYSTIME(_systime_p)	{ *(_systime_p) = kalGetTimeTick(); }

/* monotonic time since boot, which also includes the time spent in suspend */
#define GET_BOOT_SYSTIME(_systime_p)			\
	*(_systime_p) = kal_div64_u64(kalGetBootTime(), USEC_PER_MSEC)

/* The macro to copy the system time */
#define COPY_SYSTIME(_destTime, _srcTime)	{(_destTime) = (_srcTime); }

/* The macro to get the system time difference between t1 and t2 (t1 - t2) */
/* #define GET_SYSTIME_DIFFERENCE(_time1, _time2, _diffTime) \
 *	(_diffTime) = (_time1) - (_time2)
 */

/* The macro to check for the expiration, if TRUE means
 * _currentTime >= _expirationTime
 */
#define CHECK_FOR_EXPIRATION(_currentTime, _expirationTime) \
	(((uint32_t)(_currentTime) - (uint32_t)(_expirationTime)) \
	<= 0x7fffffffUL)

/* The macro to check for the timeout */
#define CHECK_FOR_TIMEOUT(_currentTime, _timeoutStartingTime, _timeout) \
	CHECK_FOR_EXPIRATION((_currentTime), \
	((_timeoutStartingTime) + (_timeout)))

/* The macro to set the expiration time with a specified timeout */
/* Watch out for round up. */
#define SET_EXPIRATION_TIME(_expirationTime, _timeout) \
	{ \
		GET_CURRENT_SYSTIME(&(_expirationTime)); \
		(_expirationTime) += (OS_SYSTIME)(_timeout); \
	}

#define timerRenewTimer(adapter, tmr, interval) \
	timerStartTimer(adapter, tmr, interval, (tmr)->function, (tmr)->data)

#define MGMT_INIT_TIMER(_adapter_p, _timer, _callbackFunc) \
	timerInitTimer(_adapter_p, &(_timer), (uint32_t)(_callbackFunc))

/*******************************************************************************
 *                  F U N C T I O N   D E C L A R A T I O N S
 *******************************************************************************
 */
void cnmTimerInitialize(struct ADAPTER *prAdapter);

void cnmTimerDestroy(struct ADAPTER *prAdapter);

void cnmTimerInitTimerOption(struct ADAPTER *prAdapter,
			     struct TIMER *prTimer,
			     PFN_MGMT_TIMEOUT_FUNC pfFunc,
			     uintptr_t ulDataPtr,
			     enum ENUM_TIMER_WAKELOCK_TYPE_T eType);

void cnmTimerStopTimer(struct ADAPTER *prAdapter, struct TIMER *prTimer);

void cnmTimerStartTimer(struct ADAPTER *prAdapter, struct TIMER *prTimer,
			uint32_t u4TimeoutMs);

void cnmTimerDoTimeOutCheck(struct ADAPTER *prAdapter);

/*******************************************************************************
 *                              F U N C T I O N S
 *******************************************************************************
 */
static __KAL_INLINE__ int32_t timerPendingTimer(struct TIMER *prTimer)
{
	ASSERT(prTimer);

	return prTimer->rLinkEntry.prNext != NULL;
}

static __KAL_INLINE__ void cnmTimerInitTimer(struct ADAPTER *prAdapter,
					     struct TIMER *prTimer,
					     PFN_MGMT_TIMEOUT_FUNC pfFunc,
					     uintptr_t ulDataPtr)
{
	cnmTimerInitTimerOption(prAdapter, prTimer, pfFunc, ulDataPtr,
		TIMER_WAKELOCK_AUTO);
}

#if CFG_WOW_SUPPORT
void cnmStopPendingJoinTimerForSuspend(struct ADAPTER *prAdapter);
#endif

#endif /* _CNM_TIMER_H */
