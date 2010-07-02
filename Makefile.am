AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

SUBDIRS = doc src

DIST_SUBDIRS = doc src

GENFILES = @PACKAGE_NAME@.spec Portfile

EXTRA_DIST = \
    @PACKAGE_NAME@.sln \
    libtool.m4 \
    acx_pthread.m4 \
    acinclude.m4 \
    $(GENFILES) \
    $(GENFILES:%=%.in) \
    depend \
	depcomp \
    config_win32.h
