AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc src

DIST_SUBDIRS = doc src

GENFILES = @PACKAGE_NAME@.spec Portfile

EXTRA_DIST = \
    @PACKAGE_NAME@.sln \
    $(GENFILES) \
    $(GENFILES:%=%.in) \
    config_win32.h
