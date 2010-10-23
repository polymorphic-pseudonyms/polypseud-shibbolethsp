/* config_win32.h.  Copied from a ./configure on Unix */

/* Define if C++ compiler supports covariant virtual methods. */
#define HAVE_COVARIANT_RETURNS 1

/* Define to 1 if C++ compiler supports nullptr keyword. */
#if _MSC_VER >= 1600
# define HAVE_NULLPTR 1
#endif

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the `gmtime_r' function. */
/* #undef HAVE_GMTIME_R */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `dmallocxx' library (-ldmallocxx). */
/* #undef HAVE_LIBDMALLOCXX */

/* Define if log4shib library is used. */
#define MYEXT_LOG4SHIB 1

/* Define if log4cpp library is used. */
/* #undef MYEXT_LOG4CPP */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* define if the compiler implements namespaces */
#define HAVE_NAMESPACES 1

/* Define if you have POSIX threads libraries and header files. */
/* #undef HAVE_PTHREAD */

/* Define to 1 if you have the <stdint.h> header file. */
/* #undef HAVE_STDINT_H */

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
/* #undef HAVE_STRCASECMP */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #undef HAVE_UNISTD_H */

/* Name of package */
#define PACKAGE "myextension"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "myextension@example.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "myextension"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "myextension 1.0"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "myextension"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0"

/* Define to the necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Version number of package */
#define VERSION "1.0"

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `unsigned' if <sys/types.h> does not define. */
/* #undef size_t */
