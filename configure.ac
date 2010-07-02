AC_PREREQ([2.50])
AC_INIT([myextension], [1.0], [myextension@example.org], [myextension])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([myextension],[1.0])

sinclude(acx_pthread.m4)

AC_ARG_ENABLE(debug,
    AC_HELP_STRING(--enable-debug, [Have GCC compile with symbols (Default = no)
]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])
AC_CANONICAL_HOST

if test "$GCC" = "yes" ; then
#    AC_HAVE_GCC_VERSION(4,0,0,0,
#        [
#        AC_DEFINE(GCC_HASCLASSVISIBILITY,1,
#            [Define to enable class visibility control in gcc.])
#        GCC_CFLAGS="$GCC_CFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        GCC_CXXFLAGS="$GCC_CXXFLAGS -fvisibility=hidden -fvisibility-inlines-hidden"
#        ])
    CFLAGS="-Wall $GCC_CFLAGS"
    CXXFLAGS="-Wall $GCC_CXXFLAGS"
else
# Fix for Sun Workshop compiler in debug mode, may be Sun case #6360993
	case "${host_cpu}-${host_os}" in
	        *solaris*)
			if test "$CXX" = "CC" ; then
				CXXFLAGS="$CXXFLAGS -Qoption ccfe -stabs=no%dfltlit+no%dflthlp"
			fi
			;;
	        *osf*)
			CXXFLAGS="$CXXFLAGS -D_POSIX_PII_SOCKET"
			;;
	esac
fi

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_LANG(C)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp])

# checks for pthreads
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

AC_LANG(C++)

# C++ requirements
AC_CXX_REQUIRE_STL
AC_CXX_NAMESPACES

# log4shib settings (favor this version over the log4cpp code)
AC_PATH_PROG(LOG4SHIB_CONFIG,log4shib-config)
AC_ARG_WITH(log4shib,
    AC_HELP_STRING([--with-log4shib=PATH], [where log4shib-config is installed]),
    [
    LOG4SHIB_CONFIG="${with_log4shib}"
    if ! test -f "${LOG4SHIB_CONFIG}" ; then
    	LOG4SHIB_CONFIG="${with_log4shib}/bin/log4shib-config"
    fi
    ])
if test -f "${LOG4SHIB_CONFIG}"; then
    LDFLAGS="`${LOG4SHIB_CONFIG} --libs` $LDFLAGS"
    CPPFLAGS="`${LOG4SHIB_CONFIG} --cflags` $CPPFLAGS"
	AC_CHECK_HEADER([log4shib/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4shib header files]))
	AC_TRY_LINK(
		[#include <log4shib/Category.hh>
#include <log4shib/CategoryStream.hh>],
		[log4shib::Category::getInstance("foo").errorStream() << log4shib::eol],
		[AC_DEFINE(MYEXT_LOG4SHIB,1,[Define if log4shib library is used.])],
		[AC_MSG_ERROR([unable to link with log4shib])])
else
    AC_MSG_WARN([log4shib-config not found, may need to use --with-log4shib option])
    AC_MSG_WARN([will look for original log4cpp library])
    
	# log4cpp settings
	AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
	AC_ARG_WITH(log4cpp,
	    AC_HELP_STRING([--with-log4cpp=PATH], [where log4cpp-config is installed]),
	    [
	    LOG4CPP_CONFIG="${with_log4cpp}"
	    if ! test -f "${LOG4CPP_CONFIG}" ; then
	    	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
	    fi
	    ])
	if test -f "${LOG4CPP_CONFIG}"; then
		AC_MSG_WARN([will try to use log4cpp, note that most non-Internet2 supplied versions are not thread-safe])
	    LDFLAGS="`${LOG4CPP_CONFIG} --libs` $LDFLAGS"
	    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
		AC_CHECK_HEADER([log4cpp/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
		AC_TRY_LINK(
			[#include <log4cpp/Category.hh>
#include <log4cpp/CategoryStream.hh>],
			[log4cpp::Category::getInstance("foo").errorStream() << log4cpp::eol],
			[AC_DEFINE(MYEXT_LOG4CPP,1,[Define if log4cpp library is used.])],
			[AC_MSG_ERROR([unable to link with log4cpp, need version 1.0 or later])])
	else
	    AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
	fi
fi

# Xerces settings
AC_ARG_WITH(xerces, 
            AC_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
            [if test x_$with_xerces != x_/usr; then
                LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
            fi])
LIBS="-lxerces-c $LIBS"
AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,
                AC_MSG_ERROR([unable to find xerces header files]))
AC_MSG_CHECKING([Xerces version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xercesc/util/XercesVersion.hpp>],
[#if  _XERCES_VERSION != 20600
int i = 0;
#else
#error cannot use version 2.6.0
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([Xerces-C v2.6.0 has bugs that inhibit use with signed XML, please use a newer version])])
AC_TRY_LINK(
        [#include <xercesc/util/PlatformUtils.hpp>],
        [xercesc::XMLPlatformUtils::Initialize()],
        [AC_DEFINE(HAVE_LIBXERCESC,1,[Define if Xerces-C library was found])],
        [AC_MSG_ERROR([unable to link with Xerces])])


#XML-Tooling settings
AC_ARG_WITH(xmltooling,
            AC_HELP_STRING([--with-xmltooling=PATH], [where xmltooling-c is installed]),
            [if test x_$with_xmltooling != x_/usr; then
                LDFLAGS="-L${with_xmltooling}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
            fi])
LITE_LIBS="-lxmltooling-lite"
XMLSEC_LIBS="-lxmltooling"
AC_CHECK_HEADER([xmltooling/base.h],,
                AC_MSG_ERROR([unable to find xmltooling header files]))

# XML-Security settings
AC_ARG_WITH(xmlsec,
            AC_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),,
            [with_xmlsec=/usr])

if test x_$with_xmlsec != x_/usr; then
    LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
    CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
fi        
XMLSEC_LIBS="-lxml-security-c $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find XML-Security header files]))
AC_MSG_CHECKING([XML-Security version])
AC_PREPROC_IFELSE(
    [AC_LANG_PROGRAM([#include <xsec/utils/XSECPlatformUtils.hpp>],
    [#if XSEC_VERSION_MAJOR > 1 || (XSEC_VERSION_MAJOR == 1 && XSEC_VERSION_MEDIUM > 3)
int i = 0;
#else
#error need version 1.4.0 or later
#endif])],
    [AC_MSG_RESULT(OK)],
    [AC_MSG_FAILURE([XML-Security version 1.4.0 or greater is required.])])
AC_TRY_LINK(
        [#include <xsec/utils/XSECPlatformUtils.hpp>],
        [XSECPlatformUtils::Initialise()],,
        [AC_MSG_ERROR([unable to link with XML-Security])])

# restore master libs
LIBS="$save_LIBS"

# OpenSAML settings
AC_ARG_WITH(saml,
    AC_HELP_STRING([--with-saml=PATH], [where saml is installed]),
    [if test x_$with_saml != x_/usr; then
        LDFLAGS="-L${with_saml}/lib $LDFLAGS"
        CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
    fi])
XMLSEC_LIBS="-lsaml $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([saml/saml2/metadata/Metadata.h],,
                AC_MSG_ERROR([unable to find OpenSAML header files]))
AC_TRY_LINK(
	[#include <saml/SAMLConfig.h>],
	[opensaml::SAMLConfig::getConfig()],
    [AC_DEFINE(HAVE_SAML,1,[Define if saml library was found])],
    [AC_MSG_ERROR([unable to link with OpenSAML])])

# restore master libs
LIBS="$save_LIBS"

# Shibboleth SP settings
AC_ARG_WITH(shibsp,
    AC_HELP_STRING([--with-shibsp=PATH], [where Shibboleth SP is installed]),
    [if test x_$with_shibsp != x_/usr; then
        LDFLAGS="-L${with_shibsp}/lib $LDFLAGS"
        CPPFLAGS="-I${with_shibsp}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lshibsp-lite $LITE_LIBS"
XMLSEC_LIBS="-lshibsp $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([shibsp/SPConfig.h],,
                AC_MSG_ERROR([unable to find Shibboleth SP header files]))
AC_TRY_LINK(
    [#include <shibsp/SPConfig.h>],
    [shibsp::SPConfig::getConfig()],
    [AC_DEFINE(HAVE_SHIBSP,1,[Define if Shibboleth SP library was found])],
    [AC_MSG_ERROR([unable to link with Shibboleth SP])])

# restore master libs
LIBS="$save_LIBS"

AC_SUBST(LITE_LIBS)
AC_SUBST(XMLSEC_LIBS)

AC_CONFIG_FILES([myextension.spec Portfile])

# output the underlying makefiles
AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])

LIBTOOL="$LIBTOOL --silent"

AC_OUTPUT
