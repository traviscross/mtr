AC_PREREQ([2.59])
AC_INIT([mtr],
  [m4_esyscmd([build-aux/git-version-gen .tarball-version])],
  [R.E.Wolff@BitWizard.nl], [],
  [http://www.BitWizard.nl/mtr/])
AC_CONFIG_SRCDIR([mtr.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([
  1.11.6
  foreign
])

# --enable-silent-rules
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_SUBST([GTK_OBJ])
AC_SUBST([CURSES_OBJ])

GTK_OBJ=gtk.o
CURSES_OBJ=curses.o

AC_PROG_CC

# Check bytes in types.
AC_CHECK_SIZEOF([unsigned char], [1])
AC_CHECK_SIZEOF([unsigned short], [2])
AC_CHECK_SIZEOF([unsigned int], [4])
AC_CHECK_SIZEOF([unsigned long], [4])

# Check headers.
AC_CHECK_HEADERS([ \
  arpa/nameser_compat.h \
  curses.h \
  cursesX.h \
  fcntl.h \
  ncurses.h \
  ncurses/curses.h \
  socket.h \
  sys/socket.h \
  sys/types.h \
  sys/xti.h \
])

# Find ncursses.
AC_SEARCH_LIBS([initscr],
  [ncurses curses cursesX],
  [],
  [AC_MSG_WARN([Building without curses display support])
  AC_DEFINE([NO_CURSES], [1], [Define if you don't have the curses libraries available.])
  CURSES_OBJ=])

AC_CHECK_LIB([ncurses],
  [use_default_colors],
  [AC_DEFINE([HAVE_USE_DEFAULT_COLORS],
    [1],
    [Define this if your curses library has the use_default_colors() command.])
  ])

# Check functions.
AC_CHECK_FUNCS([ \
  attron \
  fcntl \
])

AC_CHECK_LIB([m], [floor], [], [AC_MSG_ERROR([No math library found])])

# Find GTK
AC_ARG_WITH([gtk],
  [AS_HELP_STRING([--without-gtk], [Do not try to use GTK+ at all])],
  [], [with_gtk=yes])
AS_IF([test "x$with_gtk" = "xyes"], [WANTS_GTK=yes], [WANTS_GTK=no])

m4_ifndef([AM_PATH_GTK_2_0],
  [m4_defun([AM_PATH_GTK_2_0], [
    AC_MSG_ERROR([dnl
Could not locate the gtk2 automake macros, these are usually located in
  .../share/aclocal/gtk-2.0.m4
Before running bootstrap try setting the environment variable
  ACLOCAL_PATH="/own/dir"
or configure --without-gtk.])
  ])
])

AS_IF([test "x$WANTS_GTK" = "xyes"], [
  AM_PATH_GTK_2_0([2.6.0], [
    CFLAGS="$CFLAGS $GTK_CFLAGS"
    LIBS="$LIBS $GTK_LIBS -lm"
  ], [
    AC_MSG_WARN([Building without GTK2 display support])
    AC_DEFINE([NO_GTK], [1], [Define if you don't have the GTK+ libraries available.])
    GTK_OBJ=""
  ])
], [
  AC_DEFINE([NO_GTK], [1], [Define if you don't have the GTK+ libraries available.])
  GTK_OBJ=""
])

# Enable ipinfo
AC_ARG_WITH([ipinfo],
  [AS_HELP_STRING([--without-ipinfo], [Do not try to use ipinfo lookup at all])],
  [], [with_ipinfo=yes])
AM_CONDITIONAL([IPINFO], [test "x$with_ipinfo" = "xyes"])
AS_IF([test "x$with_ipinfo" = "xno"], [
  AC_DEFINE([NO_IPINFO], [1], [Define to disable ipinfo lookup])
])

AC_ARG_ENABLE([ipv6],
  [AS_HELP_STRING([--disable-ipv6], [Do not enable IPv6])],
  [WANTS_IPV6=$enableval], [WANTS_IPV6=yes])

USES_IPV6=
AC_CHECK_FUNC([getaddrinfo], [
  AS_IF([test "x$WANTS_IPV6" = "xyes"], [
    AC_DEFINE([ENABLE_IPV6], [1], [Define to enable IPv6])
    USES_IPV6=yes
  ])
])

AC_CHECK_FUNC([socket], [],
  [AC_CHECK_LIB([socket], [socket], [], [AC_MSG_ERROR([No socket library found])])])

AC_CHECK_FUNC([gethostbyname], [],
  [AC_CHECK_LIB([nsl], [gethostbyname], [], [AC_MSG_ERROR([No nameservice library found])])])

dnl AC_CHECK_FUNC([res_init], [], [
dnl   AC_CHECK_LIB([bind], [res_init], [], [
dnl   AC_CHECK_LIB([resolv], [res_init], [], [AC_MSG_ERROR([No resolver library found])])])])

AC_CHECK_FUNCS([seteuid])
dnl  AC_CHECK_FUNC([setuid], [], [AC_MSG_ERROR([I Need either seteuid or setuid])])

dnl AC_CHECK_FUNC([res_mkquery], [], [
dnl   AC_CHECK_LIB([bind], [res_mkquery], , [
dnl    AC_CHECK_LIB([resolv], [res_mkquery], [], [
dnl      AC_CHECK_LIB([resolv], [__res_mkquery], [],
dnl        [AC_MSG_ERROR([No resolver library found])
dnl      ])
dnl    ])
dnl  ])
dnl ])

# See if a library is needed for res_mkquery and if so put it in RESOLV_LIBS
RESOLV_LIBS=
AC_SUBST([RESOLV_LIBS])
AC_DEFUN([LIBRESOLVTEST_SRC], [
AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <resolv.h>
]], [[
int (*res_mkquery_func)(int,...) = (int (*)(int,...))res_mkquery;
(void)(*res_mkquery_func)(0);
]])])
AC_MSG_CHECKING([whether library required for res_mkquery])
RESOLV_LIB_NONE=
AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
  [AC_MSG_RESULT([no])
  RESOLV_LIB_NONE=yes],
  [AC_MSG_RESULT([yes])])

AS_IF([test "x$RESOLV_LIB_NONE" = "x"], [
  AC_MSG_CHECKING([for res_mkquery in -lbind])
  STASH_LIBS="$LIBS"
  LIBS="$STASH_LIBS -lbind"
  AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
    [AC_MSG_RESULT([yes])
    RESOLV_LIBS=-lbind],
    [AC_MSG_RESULT([no])
  ])
  AS_IF([test "x$RESOLV_LIBS" = "x"], [
    AC_MSG_CHECKING([for res_mkquery in -lresolv])
    LIBS="$STASH_LIBS -lresolv"
    AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
    [AC_MSG_RESULT([yes])
    RESOLV_LIBS=-lresolv],
    [AC_MSG_RESULT([no])
      AC_MSG_ERROR([No resolver library found])
    ])
  ])
  LIBS="$STASH_LIBS"
])

# Error printing functions.
AC_CHECK_FUNC([herror], [],
  [AC_DEFINE([NO_HERROR], [1], [Define if you don't have the herror() function available.])])
AC_CHECK_FUNC([strerror], [],
  [AC_DEFINE([NO_STRERROR], [1], [Define if you don't have the strerror() function available.])])

AC_CHECK_DECLS([errno], [], [], [[
#include <errno.h>
#include <sys/errno.h>
  ]])

AC_CHECK_TYPE([socklen_t],
  [AC_DEFINE([HAVE_SOCKLEN_T], [], [Define if your system has socklen_t])], [],
  [[#include <netinet/in.h>
#ifdef HAVE_SOCKET_H
#include <socket.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif]])

AC_CHECK_TYPE([struct in_addr],
  [AC_DEFINE([HAVE_STRUCT_INADDR], [], [Define if you have struct in_addr])], [],
  [[#include <netinet/in.h>]])

# Add C flags to display more warnings
AC_MSG_CHECKING([for C flags to get more warnings])
ac_save_CFLAGS="$CFLAGS"

AS_IF([test "x$ac_cv_c_compiler_gnu" = "xyes"], [
  dnl gcc is the easiest C compiler
  warning_CFLAGS="-Wall"
  # Check if compiler supports -Wno-pointer-sign and add it if supports
  CFLAGS_saved="$CFLAGS"
  CFLAGS="$CFLAGS -Wno-pointer-sign"
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[int foo;]])],
    [warning_CFLAGS="${warning_CFLAGS} -Wno-pointer-sign"], [])
  CFLAGS="$CFLAGS_saved"
], [
  dnl Vendor supplied C compilers are a bit tricky
  AS_CASE([$host_os],
    dnl SGI IRIX with the MipsPRO C compiler
    [irix*], [
      CFLAGS="$CFLAGS -fullwarn"
      AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM(
          [[#include <stdio.h>]],
          [[printf("test");]])],
        [warning_CFLAGS="-fullwarn"], []
      )
    ],
    dnl SunOS 4.x with the SparcWorks(?) acc compiler
    [sunos*], [
      AS_IF([test "$CC" = "acc"], [
        CFLAGS="$CFLAGS -vc"
        AC_COMPILE_IFELSE([
          AC_LANG_PROGRAM(
            [[#include <stdio.h>]],
            [[printf("test");]])],
          [warning_CFLAGS="-vc"], []
        )
      ])
    ]
    dnl Unknown, do nothing
    [*], [
      warning_CFLAGS="none"
    ]
  )
])
CFLAGS="$ac_save_CFLAGS"

AS_IF([test "$warning_CFLAGS" = "none"], [
  AC_MSG_RESULT([none])
], [
  CFLAGS="$CFLAGS $warning_CFLAGS"
  AC_MSG_RESULT([$warning_CFLAGS])
])

# Prepare config.h, Makefile, and output them.
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
