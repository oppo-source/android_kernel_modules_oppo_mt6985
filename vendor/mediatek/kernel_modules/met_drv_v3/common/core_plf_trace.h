/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 MediaTek Inc.
 */

#ifndef _CORE_PLF_TRACE_H_
#define _CORE_PLF_TRACE_H_

#define	HVALUE_SIZE	9	/* 8 chars (max value ffffffff) + 1 char (',' or NULL) */
#define	DVALUE_SIZE	12	/* 10 chars (max value 4,294,967,295) + 1 char (',' or NULL) */

char *ms_formatH(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value);
char *core_ms_formatD(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value);
char *ms_formatH_ulong(char *__restrict__ buf, unsigned int cnt,
		       unsigned long *__restrict__ value);
char *ms_formatD_ulong(char *__restrict__ buf, unsigned int cnt,
		       unsigned long *__restrict__ value);
char *ms_formatH_EOL(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value);
char *ms_formatD_EOL(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value);
char *ms_formatH_ulonglong_EOL(char *__restrict__ buf, unsigned int cnt,
				unsigned long long *__restrict__ value);

#endif	/* _CORE_PLF_TRACE_H_ */
