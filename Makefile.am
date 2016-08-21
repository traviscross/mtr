EXTRA_DIST = SECURITY img/mtr_icon.xpm

sbin_PROGRAMS = mtr
dist_man_MANS = mtr.8
install-exec-hook: 
	`setcap cap_net_raw+ep $(DESTDIR)$(sbindir)/mtr` \
	|| chmod u+s $(DESTDIR)$(sbindir)/mtr

mtr_SOURCES = mtr.c mtr.h \
              net.c net.h \
              dns.c dns.h \
              raw.c raw.h \
              split.c split.h \
              display.c display.h \
              report.c report.h \
              select.c select.h \
              mtr-curses.h \
              img/mtr_icon.xpm \
              mtr-gtk.h

if WITH_GETOPT
mtr_SOURCES += \
	portability/getopt.h \
	portability/getopt.c \
	portability/getopt1.c
endif

if WITH_IPINFO
mtr_SOURCES += asn.c asn.h
endif

if WITH_NCURSES
mtr_SOURCES += curses.c
endif

if WITH_GTK
mtr_SOURCES += gtk.c
endif

mtr_INCLUDES = $(GLIB_CFLAGS) -I$(top_builddir) -I$(top_srcdir)
mtr_CFLAGS = $(GTK_CFLAGS) $(NCURSES_CFLAGS)
mtr_LDADD = $(GTK_LIBS) $(NCURSES_LIBS) $(RESOLV_LIBS)
