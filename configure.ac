# Process this file with autoreconf
AC_PREREQ([2.50])
AC_INIT([polypseud],[1.0],[polypseud@example.org],[polypseud])
AC_CONFIG_SRCDIR(src)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Have GCC compile with symbols (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([polypseud.spec])
AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])

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
fi

# Fix for Sun Workshop compiler in debug mode, may be Sun case #6360993
case "${host_cpu}-${host_os}" in
        *solaris*)
		CFLAGS="$CFLAGS -D_POSIX_PTHREAD_SEMANTICS"
		CXXFLAGS="$CXXFLAGS -D_POSIX_PTHREAD_SEMANTICS"
		if test "$CXX" = "CC" ; then
			CXXFLAGS="$CXXFLAGS -Qoption ccfe -stabs=no%dfltlit+no%dflthlp"
		fi
		;;
        *osf*)
		CXXFLAGS="$CXXFLAGS -D_POSIX_PII_SOCKET"
		;;
esac

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
    AC_DEFINE([HAVE_PTHREAD],[1],[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

AC_LANG(C++)

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

# are covariant methods allowed?
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]],
        [[
        class base { public: virtual base *GetPtr( void ) { return this; } };
        class derived: virtual public base { public: virtual derived *GetPtr( void ) { return this; } };
        ]])],
    [AC_DEFINE([HAVE_COVARIANT_RETURNS],[1],[Define to 1 if C++ compiler supports covariant virtual methods.])])

# is nullptr supported?
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[]],[[const char* ptr = nullptr;]])],
    [AC_DEFINE([HAVE_NULLPTR],[1],[Define to 1 if C++ compiler supports nullptr keyword.])])

# log4shib settings (favor this version over the log4cpp code)
AC_PATH_PROG(LOG4SHIB_CONFIG,log4shib-config)
AC_ARG_WITH(log4shib,
    AS_HELP_STRING([--with-log4shib=PATH],[where log4shib-config is installed]),
    [
    LOG4SHIB_CONFIG="${with_log4shib}"
    if ! test -f "${LOG4SHIB_CONFIG}" ; then
    	LOG4SHIB_CONFIG="${with_log4shib}/bin/log4shib-config"
    fi
    ])
if test -f "${LOG4SHIB_CONFIG}"; then
    LIBS="`${LOG4SHIB_CONFIG} --libs` $LIBS"
    CPPFLAGS="`${LOG4SHIB_CONFIG} --cflags` $CPPFLAGS"
	AC_CHECK_HEADER([log4shib/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4shib header files]))
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <log4shib/Category.hh>
#include <log4shib/CategoryStream.hh>]],
            [[log4shib::Category::getInstance("foo").errorStream() << log4shib::eol]])],
        [AC_DEFINE([MYEXT_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
        [AC_MSG_ERROR([unable to link with log4shib])])
else
    AC_MSG_WARN([log4shib-config not found, may need to use --with-log4shib option])
    AC_MSG_WARN([will look for original log4cpp library])
    
	# log4cpp settings
	AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
	AC_ARG_WITH(log4cpp,
	    AS_HELP_STRING([--with-log4cpp=PATH],[where log4cpp-config is installed]),
	    [
	    LOG4CPP_CONFIG="${with_log4cpp}"
	    if ! test -f "${LOG4CPP_CONFIG}" ; then
	    	LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"
	    fi
	    ])
	if test -f "${LOG4CPP_CONFIG}"; then
		AC_MSG_WARN([will try to use log4cpp, note that most non-Internet2 supplied versions are not thread-safe])
	    LIBS="`${LOG4CPP_CONFIG} --libs` $LIBS"
	    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
		AC_CHECK_HEADER([log4cpp/CategoryStream.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([[#include <log4cpp/Category.hh>
#include <log4cpp/CategoryStream.hh>]],
                [[log4cpp::Category::getInstance("foo").errorStream() << log4cpp::eol]])],
            [AC_DEFINE([MYEXT_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])],
            [AC_MSG_ERROR([unable to link with log4cpp, need version 1.0 or later])])
	else
	    AC_MSG_ERROR([log4cpp-config not found, may need to use --with-log4cpp option])
	fi
fi

# Xerces settings
AC_ARG_WITH(xerces, 
    AS_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
    [if test x_$with_xerces != x_/usr; then
        LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
    fi])
LIBS="-lxerces-c $LIBS"
AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,AC_MSG_ERROR([unable to find xerces header files]))
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
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <xercesc/util/PlatformUtils.hpp>]],
        [[xercesc::XMLPlatformUtils::Initialize()]])],
    ,[AC_MSG_ERROR([unable to link with Xerces])])


#XML-Tooling settings
AC_ARG_WITH(xmltooling,
    AS_HELP_STRING([--with-xmltooling=PATH],[where xmltooling-c is installed]),
    [if test x_$with_xmltooling != x_/usr; then
        LDFLAGS="-L${with_xmltooling}/lib $LDFLAGS"
        CPPFLAGS="-I${with_xmltooling}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lxmltooling-lite"
XMLSEC_LIBS="-lxmltooling"
AC_CHECK_HEADER([xmltooling/base.h],,AC_MSG_ERROR([unable to find xmltooling header files]))

# XML-Security settings
AC_ARG_WITH(xmlsec,
    AS_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),,
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
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <xsec/utils/XSECPlatformUtils.hpp>]],
            [[XSECPlatformUtils::Initialise()]])],,
        [AC_MSG_ERROR([unable to link with XML-Security])])

# restore master libs
LIBS="$save_LIBS"

# OpenSAML settings
AC_ARG_WITH(saml,
    AS_HELP_STRING([--with-saml=PATH],[where saml is installed]),
    [if test x_$with_saml != x_/usr; then
        LDFLAGS="-L${with_saml}/lib $LDFLAGS"
        CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
    fi])
XMLSEC_LIBS="-lsaml $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([saml/saml2/metadata/Metadata.h],,AC_MSG_ERROR([unable to find OpenSAML header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <saml/SAMLConfig.h>]],
	[[opensaml::SAMLConfig::getConfig()]])],
    ,[AC_MSG_ERROR([unable to link with OpenSAML])])

# restore master libs
LIBS="$save_LIBS"

# Shibboleth SP settings
AC_ARG_WITH(shibsp,
    AS_HELP_STRING([--with-shibsp=PATH],[where Shibboleth SP is installed]),
    [if test x_$with_shibsp != x_/usr; then
        LDFLAGS="-L${with_shibsp}/lib $LDFLAGS"
        CPPFLAGS="-I${with_shibsp}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lshibsp-lite $LITE_LIBS"
XMLSEC_LIBS="-lshibsp $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([shibsp/SPConfig.h],,AC_MSG_ERROR([unable to find Shibboleth SP header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <shibsp/SPConfig.h>]],
    [[shibsp::SPConfig::getConfig()]])],
    ,[AC_MSG_ERROR([unable to link with Shibboleth SP])])

# restore master libs
LIBS="$save_LIBS"

# OpenSSL settings
AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl=PATH],[where OpenSSL is installed]),
    [if test x_$with_openssl != x_/usr; then
        LDFLAGS="-L${with_openssl}/lib $LDFLAGS"
        CPPFLAGS="-I${with_openssl}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lcrypto $LITE_LIBS"
XMLSEC_LIBS="-lcrypto $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([openssl/bn.h],,AC_MSG_ERROR([unable to find OpenSSL header files]))
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[#include <openssl/bn.h>]],
    [[BN_new()]])],
    ,[AC_MSG_ERROR([unable to link with OpenSSL libcrypto])])

# restore master libs
LIBS="$save_LIBS"

# polypseud settings
AC_ARG_WITH(polypseud,
    AS_HELP_STRING([--with-polypseud=PATH],[where libpolypseud is installed]),
    [if test x_$with_polypseud != x_/usr; then
        LDFLAGS="-L${with_polypseud}/lib $LDFLAGS"
        CPPFLAGS="-I${with_polypseud}/include $CPPFLAGS"
    fi])
LITE_LIBS="-lpolypseud $LITE_LIBS"
XMLSEC_LIBS="-lpolypseud $XMLSEC_LIBS"

# save and append master libs
save_LIBS="$LIBS"
LIBS="$XMLSEC_LIBS $LIBS"

AC_CHECK_HEADER([polypseud.h],,AC_MSG_ERROR([unable to find polypseud header file]))
dnl AC_LINK_IFELSE(
dnl    [AC_LANG_PROGRAM([[#include <polypseud.h>]],
dnl    [[decrypt_ep(
dnl        "Ama2GQ6MPNx1Zw5PohRi0+Y/7I6KuM+DhgKcFUzxaPaTamnTqYjpP30=,AsrpLpp50tAltgN6ZSe56aYQyqjoiIqhOrT/5F+oJRzoy1Vf0ejlH28=,A4C/yLQrUrE0UQ5W2/8IH5P07kzLz9UW/58kGP+r2HO6Uoj8R7lSXH4=",
dnl        "15A16B2445F6255B6BA5CF47A0DE7AED8BEA1453523D6A05E785024EC79EBCFE925410B9991166E5",
dnl        "58F5B792106F4B1F944F2AA661765E9199D210DCB8F17AB638F316862BC517CC51AFB2B9C676CE09")]])],
dnl    ,[AC_MSG_ERROR([unable to link with polypseud library])])

# restore master libs
LIBS="$save_LIBS"

AC_SUBST(LITE_LIBS)
AC_SUBST(XMLSEC_LIBS)

LIBTOOL="$LIBTOOL --silent"

AC_OUTPUT
