/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ERROR_H
# include <error.h>
#else
# include "portability/error.h"
#endif

#include "utils.h"

extern char *trim(char *s)
{
  char *p = s;
  int l = strlen(p);

  while (isspace(p[l - 1]) && l)
    p[--l] = 0;
  while (*p && isspace(*p) && l)
    ++p, --l;

  return p;
}

/* Parse string, and return positive signed int. */
extern int strtonum_or_err(const char *str, const char *errmesg, const int type)
{
  unsigned long int num;
  char *end = NULL;

  if (str != NULL && *str != '\0') {
    errno = 0;
    num = strtoul(str, &end, 10);
    if (errno == 0 && str != end && end != NULL && *end == '\0') {
      switch (type) {
      case STRTO_INT:
        if (num < INT_MAX)
          return num;
        break;
      case STRTO_U32INT:
        if (num < UINT32_MAX)
          return num;
        break;
      }
    }
  }
  error(EXIT_FAILURE, errno, "%s: '%s'", errmesg, str);
  return 0;
}

extern float strtofloat_or_err(const char *str, const char *errmesg)
{
  double num;
  char *end = NULL;

  if (str != NULL && *str != '\0') {
    errno = 0;
    num = strtod(str, &end);
    if (errno == 0 && str != end && end != NULL && *end == '\0'
#ifdef FLT_MAX
        && num < FLT_MAX
#endif
        )
      return num;
  }
  error(EXIT_FAILURE, errno, "%s: '%s'", errmesg, str);
  return 0;
}

extern void *xmalloc(const size_t size)
{
  void *ret = malloc(size);

  if (!ret && size)
    error(EXIT_FAILURE, errno, "cannot allocate %zu bytes", size);
  return ret;
}

extern char *xstrdup(const char *str)
{
  char *ret;

  if (!str)
    return NULL;
  ret = strdup(str);
  if (!ret)
    error(EXIT_FAILURE, errno, "cannot duplicate string: %s", str);
  return ret;
}
