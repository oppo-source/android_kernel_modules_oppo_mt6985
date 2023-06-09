// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "met_drv.h"
#include "interface.h"
#include "trace.h"
#include "mtk_typedefs.h"

char *ms_formatH(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%x", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%x,%x", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%x,%x,%x", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%x,%x,%x,%x", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%x,%x,%x,%x", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\0';

	return s;
}
EXPORT_SYMBOL(ms_formatH);

char *ms_formatD(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%u", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%u,%u", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%u,%u,%u", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%u,%u,%u,%u", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%u,%u,%u,%u", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\0';

	return s;
}
EXPORT_SYMBOL(ms_formatD);

char *ms_formatH_ulong(char *__restrict__ buf, unsigned int cnt, unsigned long *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%lx", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%lx,%lx", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%lx,%lx,%lx", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%lx,%lx,%lx,%lx", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%lx,%lx,%lx,%lx", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\0';

	return buf;
}
EXPORT_SYMBOL(ms_formatH_ulong);

char *ms_formatD_ulong(char *__restrict__ buf, unsigned int cnt, unsigned long *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%lu", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%lu,%lu", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%lu,%lu,%lu", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%lu,%lu,%lu,%lu", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%lu,%lu,%lu,%lu", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\0';

	return buf;
}
EXPORT_SYMBOL(ms_formatD_ulong);

char *ms_formatH_EOL(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%x", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%x,%x", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%x,%x,%x", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%x,%x,%x,%x", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%x,%x,%x,%x", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\n';
	s[1] = '\0';

	return s + 1;
}
EXPORT_SYMBOL(ms_formatH_EOL);

char *ms_formatD_EOL(char *__restrict__ buf, unsigned int cnt, unsigned int *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%u", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%u,%u", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%u,%u,%u", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%u,%u,%u,%u", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%u,%u,%u,%u", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\n';
	s[1] = '\0';

	return s + 1;
}
EXPORT_SYMBOL(ms_formatD_EOL);

char *ms_formatH_ulonglong_EOL(char *__restrict__ buf,
						unsigned int cnt,
						unsigned long long *__restrict__ value)
{
	char *s = buf;
	int len;

	if (cnt == 0) {
		buf[0] = '\0';
		return buf;
	}

	switch (cnt % 4) {
	case 1:
		len = SPRINTF(s, "%llx", value[0]);
		s += len;
		value += 1;
		cnt -= 1;
		break;
	case 2:
		len = SPRINTF(s, "%llx,%llx", value[0], value[1]);
		s += len;
		value += 2;
		cnt -= 2;
		break;
	case 3:
		len = SPRINTF(s, "%llx,%llx,%llx", value[0], value[1], value[2]);
		s += len;
		value += 3;
		cnt -= 3;
		break;
	case 0:
		len = SPRINTF(s, "%llx,%llx,%llx,%llx", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
		break;
	}

	while (cnt) {
		len = SPRINTF(s, ",%llx,%llx,%llx,%llx", value[0], value[1], value[2], value[3]);
		s += len;
		value += 4;
		cnt -= 4;
	}

	s[0] = '\n';
	s[1] = '\0';

	return s + 1;
}
EXPORT_SYMBOL(ms_formatH_ulonglong_EOL);
