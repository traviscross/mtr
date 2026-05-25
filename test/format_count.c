/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2026  Darafei Praliaskouski

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ui/format.h"

static void check_count(
    int value,
    const char *expected)
{
    char buf[6];

    memset(buf, 0, sizeof(buf));
    mtr_format_count(value, 5, buf);

    if (strcmp(buf, expected) != 0) {
        fprintf(stderr, "%d formatted as '%s', expected '%s'\n",
                value, buf, expected);
        exit(EXIT_FAILURE);
    }
}

int main(
    void)
{
    check_count(-1, "  n/a");
    check_count(0, "    0");
    check_count(99999, "99999");
    check_count(100000, "100k0");
    check_count(100099, "100k0");
    check_count(100100, "100k1");
    check_count(999999, "999k9");
    check_count(1000000, "1M000");
    check_count(9999999, "9M999");
    check_count(10000000, "10M00");
    check_count(99999999, "99M99");
    check_count(100000000, "100M0");
    check_count(999999999, "999M9");
    check_count(1000000000, "1G000");

    return EXIT_SUCCESS;
}
