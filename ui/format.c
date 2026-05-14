/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2026  Darafei Praliaskouski

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.
*/

#include "config.h"

#include <stdio.h>

#include "format.h"

char *mtr_format_count(
    int n,
    int width,
    char *buf)
{
    if (width != 5)
        /* XXX todo: implement width != 5. */
        snprintf(buf, width + 1, "%s", "unimpl");
    else if (n < 0)
        snprintf(buf, width + 1, "%5s", "n/a");
    else if (n < 100000)
        snprintf(buf, width + 1, "%5d", n);
    else if (n < 1000000)
        snprintf(buf, width + 1, "%3dk%1d", n / 1000, (n % 1000) / 100);
    else if (n < 10000000)
        snprintf(buf, width + 1, "%1dM%03d", n / 1000000,
                 (n % 1000000) / 1000);
    else if (n < 100000000)
        snprintf(buf, width + 1, "%2dM%02d", n / 1000000,
                 (n % 1000000) / 10000);
    else if (n < 1000000000)
        snprintf(buf, width + 1, "%3dM%01d", n / 1000000,
                 (n % 1000000) / 100000);
    else
        snprintf(buf, width + 1, "%1dG%03d", n / 1000000000,
                 (n % 1000000000) / 1000000);

    return buf;
}
