AC_INIT([mtr], [0.85])
AC_CONFIG_SRCDIR([mtr.c])
AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_FILES([version.h.tmp:version.h.in])

AC_SUBST(GTK_OBJ)
AC_SUBST(CURSES_OBJ)

GTK_OBJ=gtk.o
CURSES_OBJ=curses.o

AC_PROG_CC

AC_CHECK_SIZEOF(unsigned char, 1)
AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)

AC_CHECK_HEADERS(ncurses.h ncurses/curses.h curses.h cursesX.h sys/types.h fcntl.h)
AC_CHECK_HEADERS(socket.h sys/socket.h sys/xti.h arpa/nameser_compat.h)

# We don't refer to any symbols in termcap, but -lcurses on SunOS does.
# We have to trust the linker not to mess things up... (It should not
# pull in anything if we don't refer to anything in the lib). 
AC_CHECK_LIB(termcap, tgetent)
AC_CHECK_LIB(tinfo, tgetent)

AC_CHECK_FUNC(initscr, , 
  AC_CHECK_LIB(ncurses, initscr, , 
    AC_CHECK_LIB(curses, initscr, , 
      AC_CHECK_LIB(cursesX, initscr, , 
	AC_MSG_WARN(Building without curses display support)
	AC_DEFINE(NO_CURSES, 1, Define if you don't have the curses libraries available.)
	CURSES_OBJ=))))

AC_CHECK_FUNCS(attron fcntl)

AC_CHECK_LIB(m, floor, , AC_MSG_ERROR(No math library found))

AC_ARG_WITH(gtk,
[  --without-gtk           Do not try to use GTK+ at all],
WANTS_GTK=$withval, WANTS_GTK=yes)

AC_ARG_WITH([ipinfo],
[  --without-ipinfo        Do not try to use ipinfo lookup at all],
[ipinfo="${withval}"], [ipinfo=yes])
AM_CONDITIONAL([IPINFO], [test x$ipinfo = xyes])

AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          Do not enable IPv6],
WANTS_IPV6=$enableval, WANTS_IPV6=yes)

m4_ifndef([AM_PATH_GTK_2_0], [m4_defun([AM_PATH_GTK_2_0], [AC_MSG_ERROR([
  Could not locate the gtk2 automake macros, these are usually located in
    .../share/aclocal/gtk-2.0.m4
  Before running bootstrap try setting the environment variable
    ACLOCAL_PATH="/own/dir"
  or configure --without-gtk.
])])])
   
if test "x$WANTS_GTK" = "xyes"; then
        AM_PATH_GTK_2_0(2.6.0, CFLAGS="$CFLAGS $GTK_CFLAGS"
                           LIBS="$LIBS $GTK_LIBS -lm",
                           AC_MSG_WARN(Building without GTK2 display support)
                   AC_DEFINE(NO_GTK, 1, [Define if you don't have the GTK+ libraries available.])
                           GTK_OBJ="")
else
	AC_DEFINE(NO_GTK)
	GTK_OBJ=""
fi

if test "x$ipinfo" = "xno"; then
	AC_DEFINE([NO_IPINFO], [1], [Define to disable ipinfo lookup])
fi

AC_CHECK_FUNC(socket, , 
  AC_CHECK_LIB(socket, socket, , AC_MSG_ERROR(No socket library found)))

AC_CHECK_FUNC(gethostbyname, ,
  AC_CHECK_LIB(nsl, gethostbyname, , AC_MSG_ERROR(No nameservice library found)))

#AC_CHECK_FUNC(res_init, , 
#  AC_CHECK_LIB(bind, res_init, , 
#   AC_CHECK_LIB(resolv, res_init, , AC_MSG_ERROR(No resolver library found))))

AC_CHECK_FUNCS(seteuid)
#  AC_CHECK_FUNC(setuid, , AC_MSG_ERROR (I Need either seteuid or setuid))

#AC_CHECK_FUNC(res_mkquery, ,
#  AC_CHECK_LIB(bind, res_mkquery, ,
#   AC_CHECK_LIB(resolv, res_mkquery, ,
#     AC_CHECK_LIB(resolv, __res_mkquery, , AC_MSG_ERROR(No resolver library found)))))

# See if a library is needed for res_mkquery and if so put it in RESOLV_LIBS
RESOLV_LIBS=
AC_SUBST(RESOLV_LIBS)
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
if test "x$RESOLV_LIB_NONE" = "x"; then
	AC_MSG_CHECKING([for res_mkquery in -lbind])
	STASH_LIBS="$LIBS"
	LIBS="$STASH_LIBS -lbind"
	AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
		[AC_MSG_RESULT([yes])
		RESOLV_LIBS=-lbind],
		[AC_MSG_RESULT([no])])
	if test "x$RESOLV_LIBS" = "x"; then
		AC_MSG_CHECKING([for res_mkquery in -lresolv])
		LIBS="$STASH_LIBS -lresolv"
		AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
			[AC_MSG_RESULT([yes])
			RESOLV_LIBS=-lresolv],
			[AC_MSG_RESULT([no])
                        AC_MSG_ERROR(No resolver library found)])
	fi
	LIBS="$STASH_LIBS"
fi

AC_CHECK_FUNC(herror, , AC_DEFINE(NO_HERROR, 1, [Define if you don't have the herror() function available.]))
AC_CHECK_FUNC(strerror, , AC_DEFINE(NO_STRERROR, 1, [Define if you don't have the strerror() function available.]))

USES_IPV6=
AC_CHECK_FUNC(getaddrinfo,
[if test "$WANTS_IPV6" = "yes"; then
	AC_DEFINE([ENABLE_IPV6], [], [Define to enable IPv6])
	USES_IPV6=yes
fi])

AC_CHECK_DECLS(errno, , , [[
#include <errno.h>
#include <sys/errno.h>
]] )

AC_CHECK_TYPE(socklen_t, AC_DEFINE([HAVE_SOCKLEN_T], [], [Define if your system has socklen_t]) , , [[
#include <netinet/in.h>
#ifdef HAVE_SOCKET_H
#include <socket.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])

AC_CHECK_TYPE(struct in_addr, AC_DEFINE([HAVE_STRUCT_INADDR], [], [Define if you have struct in_addr]), , [[
#include <netinet/in.h>
]])

dnl Add C flags to display more warnings
AC_MSG_CHECKING(for C flags to get more warnings)
ac_save_CFLAGS="$CFLAGS"
if test "x$ac_cv_c_compiler_gnu" = "xyes" ; then
  dnl gcc is the easiest C compiler
  warning_CFLAGS="-Wall"
  # Check if compiler supports -Wno-pointer-sign and add it if supports
  CFLAGS_saved="$CFLAGS"
  CFLAGS="$CFLAGS -Wno-pointer-sign"
  AC_COMPILE_IFELSE([ AC_LANG_SOURCE([[ int foo; ]])],
                  [ warning_CFLAGS="${warning_CFLAGS} -Wno-pointer-sign" ],)
  CFLAGS="$CFLAGS_saved"
else
  dnl Vendor supplied C compilers are a bit tricky
  case "$host_os" in
    dnl SGI IRIX with the MipsPRO C compiler
    irix*)
      CFLAGS="$CFLAGS -fullwarn"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[printf("test");]])],[warning_CFLAGS="-fullwarn"],[])
      ;;

    dnl SunOS 4.x with the SparcWorks(?) acc compiler
    sunos*)
        if "$CC" = "acc" ; then
          CFLAGS="$CFLAGS -vc"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[printf("test");]])],[warning_CFLAGS="-vc"],[])
        fi
      ;;

    dnl Unknown, do nothing
    *)
      warning_CFLAGS="none"
      ;;
  esac
fi
CFLAGS="$ac_save_CFLAGS"
if test "$warning_CFLAGS" = "none" ; then
  AC_MSG_RESULT(none)
else
  CFLAGS="$CFLAGS $warning_CFLAGS"
  AC_MSG_RESULT($warning_CFLAGS)
fi




AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile img/Makefile])
AC_OUTPUT

