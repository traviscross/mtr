/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2026  Darafei Praliaskouski

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.
*/

#ifndef MTR_FORMAT_H
#define MTR_FORMAT_H

#include <stddef.h>

char *mtr_format_count(
    int n,
    int width,
    char *buf);

char *mtr_format_latency_ms(
    int usec,
    char *buf,
    size_t buf_size);

#endif
