AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/shibboleth
plugin_LTLIBRARIES = polypseud.la polypseud-lite.la

polypseud_la_SOURCES = \
	@PACKAGE_NAME@.cpp

polypseud_lite_la_SOURCES = \
	@PACKAGE_NAME@.cpp

polypseud_la_LDFLAGS = -module -avoid-version
polypseud_la_LIBADD = $(XMLSEC_LIBS)
polypseud_lite_la_LDFLAGS = -module -avoid-version
polypseud_lite_la_LIBADD = $(LITE_LIBS)
polypseud_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = @PACKAGE_NAME@.vcxproj @PACKAGE_NAME@-lite.vcxproj resource.h @PACKAGE_NAME@.rc
