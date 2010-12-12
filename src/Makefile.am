AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/shibboleth
plugin_LTLIBRARIES = myextension.la myextension-lite.la

myextension_la_SOURCES = \
	@PACKAGE_NAME@.cpp

myextension_lite_la_SOURCES = \
	@PACKAGE_NAME@.cpp

myextension_la_LDFLAGS = -module -avoid-version
myextension_la_LIBADD = $(XMLSEC_LIBS)
myextension_lite_la_LDFLAGS = -module -avoid-version
myextension_lite_la_LIBADD = $(LITE_LIBS)
myextension_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = @PACKAGE_NAME@.vcxproj @PACKAGE_NAME@-lite.vcxproj resource.h @PACKAGE_NAME@.rc
