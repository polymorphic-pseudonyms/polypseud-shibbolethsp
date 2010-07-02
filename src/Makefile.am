AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/shibboleth
plugin_LTLIBRARIES = @PACKAGE_NAME@.la @PACKAGE_NAME@-lite.la

myextension_la_SOURCES = \
	@PACKAGE_NAME@.cpp

myextension_lite_la_SOURCES = \
	@PACKAGE_NAME@.cpp

myextension_la_LDFLAGS = -module -avoid-version $(XMLSEC_LIBS)
myextension_lite_la_LDFLAGS = -module -avoid-version $(LITE_LIBS)
myextension_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = @PACKAGE_NAME@.vcxproj @PACKAGE_NAME@-lite.vcxproj resource.h @PACKAGE_NAME@.rc
