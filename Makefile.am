EXTRA_DIST = \
	SECURITY \
	mtr.bat \
	img/mtr_icon.xpm \
	packet/testpacket.py \
	packet/lint.sh

sbin_PROGRAMS = mtr mtr-packet
TESTS = packet/testpacket.py

PATHFILES =
CLEANFILES = $(PATHFILES)
EXTRA_DIST += $(PATHFILES:=.in)
edit_cmd = sed \
	-e 's|@VERSION[@]|$(VERSION)|g'

%.8: $(srcdir)/%.8.in
	@ rm -f $@ $@.tmp
	$(AM_V_at) $(MKDIR_P) $$(dirname $@)
	$(AM_V_GEN) srcdir=''; \
		test -f ./$@.in || srcdir=$(srcdir)/; \
		$(edit_cmd) $${srcdir}$@.in >$@.tmp
	@ mv $@.tmp $@

$(PATHFILES): Makefile

dist_man_MANS = mtr.8 mtr-packet.8
PATHFILES += mtr.8 mtr-packet.8

install-exec-hook: 
	`setcap cap_net_raw+ep $(DESTDIR)$(sbindir)/mtr-packet` \
	|| chmod u+s $(DESTDIR)$(sbindir)/mtr-packet

mtr_SOURCES = mtr.c mtr.h \
              net.c net.h \
              dns.c dns.h \
              raw.c raw.h \
              split.c split.h \
              display.c display.h \
              report.c report.h \
              select.c select.h \
              utils.c utils.h \
              packet/cmdparse.c packet/cmdparse.h \
              mtr-curses.h \
              img/mtr_icon.xpm \
              mtr-gtk.h

if WITH_ERROR
mtr_SOURCES += \
	portability/error.h \
	portability/error.c
endif

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


mtr_packet_SOURCES = \
	packet/packet.c \
	packet/cmdparse.c packet/cmdparse.h \
	packet/command.c packet/command.h \
	packet/platform.h \
	packet/probe.c packet/probe.h \
	packet/protocols.h \
	packet/timeval.c packet/timeval.h \
	packet/wait.h


if CYGWIN

mtr_packet_SOURCES += \
	packet/command_cygwin.c packet/command_cygwin.h \
	packet/probe_cygwin.c packet/probe_cygwin.h \
	packet/wait_cygwin.c
mtr_packet_LDADD = -lcygwin -licmp -lws2_32

dist_windows_aux = \
	$(srcdir)/mtr.bat \
	$(srcdir)/AUTHORS \
	$(srcdir)/COPYING \
	$(srcdir)/README \
	$(srcdir)/NEWS

distwindir = $(distdir)-win-$(host_cpu)

#  Bundle necessary files for a Windows binary distribution
distdir-win: $(dist_windows_aux) mtr.exe mtr-packet.exe
	rm -fr $(distwindir)
	mkdir -p $(distwindir) $(distwindir)/bin $(distwindir)/terminfo
	cp $(dist_windows_aux) -t $(distwindir)
	cp mtr.exe mtr-packet.exe -t $(distwindir)/bin
	ldd mtr.exe | grep -v cygdrive | awk '{ print $$3 }' | xargs cp -t $(distwindir)/bin
	cp `find /usr/share/terminfo -name cygwin | xargs dirname` -r $(distwindir)/terminfo

#  Zip up a Windows binary distribution
dist-windows-bin: distdir-win
	rm -f $(distwindir).zip
	zip -rq $(distwindir).zip $(distwindir)
	rm -fr $(distwindir)

else  # if CYGWIN

mtr_packet_SOURCES += \
	packet/command_unix.c packet/command_unix.h \
	packet/probe_unix.c packet/probe_unix.h \
	packet/wait_unix.c

endif  # if CYGWIN


if BUILD_BASH_COMPLETION
dist_bashcompletion_DATA = bash-completion/mtr
endif
