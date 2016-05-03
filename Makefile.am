SUBDIRS = img

sbin_PROGRAMS = mtr
man_MANS = mtr.8
install-exec-hook: 
	`setcap cap_net_raw+ep $(DESTDIR)$(sbindir)/mtr` \
	|| chmod u+s $(DESTDIR)$(sbindir)/mtr

mtr_SOURCES = mtr.c \
              net.c net.h \
              dns.c dns.h \
              raw.c raw.h \
              split.c split.h \
              display.c display.h \
              report.c report.h \
              getopt.c getopt1.c getopt.h \
              select.c select.h \
              mtr-curses.h \
              mtr-gtk.h

if IPINFO
mtr_SOURCES += asn.c asn.h
endif

nodist_mtr_SOURCES = version.h
EXTRA_mtr_SOURCES = curses.c \
                    gtk.c
DEFAULT_INCLUDES= $(GLIB_CFLAGS) -I.
mtr_DEPENDENCIES = $(GTK_OBJ) $(CURSES_OBJ)
mtr_LDFLAGS = $(GTK_OBJ) $(CURSES_OBJ)
mtr_LDADD = $(GLIB_LIBS) $(RESOLV_LIBS)

CLEANFILES = version.h
BUILT_SOURCES = version.h

version.h: version.h.tmp Makefile $(mtr_SOURCES)
	@cat version.h.tmp > $@; \
	if [ -d .git ] && [ -n "$$(which git)" ]; then \
	  xver="+git:$$(git rev-list -n1 --abbrev=8 --abbrev-commit HEAD)"; \
	  sed \
	    -e "/#define *MTR_VERSION */{s/\"\([^\"]*\)\"/\"\1$$xver\"/;}" \
	    version.h.tmp > $@; \
	fi;

EXTRA_DIST = SECURITY mtr.8 Makefile Makefile.dist
distclean-local:
	(sleep 3; cp Makefile.dist Makefile) &
	rm -f *.orig

DISTCLEANFILES = *~

