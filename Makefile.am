SUBDIRS = img

sbin_PROGRAMS = mtr
man_MANS = mtr.8
install-exec-am: 
	chmod u+s $(sbindir)/mtr

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
EXTRA_mtr_SOURCES = curses.c \
                    gtk.c
mtr_DEPENDENCIES = $(GTK_OBJ) $(CURSES_OBJ)
mtr_LDFLAGS = $(GTK_OBJ) $(CURSES_OBJ)

EXTRA_DIST = SECURITY mtr.8 Makefile Makefile.dist
distclean-local:
	cp Makefile.dist Makefile

DISTCLEANFILES = *~

