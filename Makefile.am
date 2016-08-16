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
              getopt.c getopt1.c getopt.h \
              select.c select.h \
              mtr-curses.h \
              img/mtr_icon.xpm \
              mtr-gtk.h

if IPINFO
mtr_SOURCES += asn.c asn.h
endif

EXTRA_mtr_SOURCES = curses.c \
                    gtk.c

mtr_INCLUDES = $(GLIB_CFLAGS) -I$(top_builddir) -I$(top_srcdir)
mtr_DEPENDENCIES = $(GTK_OBJ) $(CURSES_OBJ)
mtr_LDFLAGS = $(GTK_OBJ) $(CURSES_OBJ)
mtr_LDADD = $(GLIB_LIBS) $(RESOLV_LIBS)
