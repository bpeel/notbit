AC_INIT([notbit], 0.1)

AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build/autotools])
AC_CONFIG_SRCDIR([src/main.c])
AM_CONFIG_HEADER([config.h])
AC_GNU_SOURCE

AC_C_BIGENDIAN([AC_DEFINE([HAVE_BIG_ENDIAN], [1], [System is big-endian])],
               [AC_DEFINE([HAVE_LITTLE_ENDIAN], [1],
                          [System is little-endian])])

alignof_name=""
AC_MSG_CHECKING([for alignof])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([const int thing = alignof (int);],
                                   [(void) 0])],
                  [alignof_name="alignof"
                   AC_MSG_RESULT([yes])],
                  [AC_MSG_RESULT([no])])
AC_MSG_CHECKING([for __alignof__])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([const int thing = __alignof__ (int);],
                                   [(void) 0])],
                  [alignof_name="__alignof__"
                   AC_MSG_RESULT([yes])],
                  [AC_MSG_RESULT([no])])
AS_IF([test "x$alignof_name" = "x"],
      [AC_MSG_ERROR([No operator for alignof found])])
AC_DEFINE_UNQUOTED([ALIGNOF_NAME], [$alignof_name],
                   [The name of the alignof operator])

AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-xz tar-ustar])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl     ============================================================
dnl     Enable strict compiler flags
dnl     ============================================================

# use strict compiler flags only when building from git; the rules for
# distcheck will take care of turning this on when making a release
m4_define([maintainer_default], [yes])
AC_ARG_ENABLE(
  [maintainer-flags],
  [AC_HELP_STRING([--enable-maintainer-flags=@<:@no/yes/error@:>@],
                  [Use strict compiler flags @<:@default=]maintainer_default[@:>@])],
  [],
  enable_maintainer_flags=maintainer_default
)

MAINTAINER_COMPILER_FLAGS="-Wall -Wcast-align -Wuninitialized
                           -Wno-strict-aliasing -Wempty-body -Wformat
                           -Wformat-security -Winit-self -Wundef
                           -Wdeclaration-after-statement
                           -Wpointer-arith -Wmissing-declarations"

AS_CASE(
  [$enable_maintainer_flags],
  [yes],
  [
    AS_COMPILER_FLAGS([MAINTAINER_CFLAGS], [$MAINTAINER_COMPILER_FLAGS])
  ],
  [no],
  [
  ],
  [error],
  [
    MAINTAINER_COMPILER_FLAGS="$MAINTAINER_COMPILER_FLAGS -Werror"
    AS_COMPILER_FLAGS([MAINTAINER_CFLAGS], [$MAINTAINER_COMPILER_FLAGS])
  ],
  [*],
  [AC_MSG_ERROR([Invalid option for --enable-maintainer-flags])]
)

# strip leading spaces
NOTBIT_EXTRA_CFLAGS="$NOTBIT_EXTRA_CFLAGS ${MAINTAINER_CFLAGS#*  }"

AC_PROG_CC

PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.32 gio-2.0 >= 2.32 gthread-2.0 >= 2.32])
PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto])

AC_SUBST(NOTBIT_EXTRA_CFLAGS)

AC_CONFIG_FILES([
        Makefile
        src/Makefile
])

AC_OUTPUT
