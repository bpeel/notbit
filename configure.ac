AC_INIT([notbit], 0.2)

AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([build/autotools])
AC_CONFIG_SRCDIR([src/main.c])
AM_CONFIG_HEADER([config.h])
AC_GNU_SOURCE

AC_PROG_CC
AC_PROG_LN_S

AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-xz tar-ustar])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

NOTBIT_EXTRA_CFLAGS=""
NOTBIT_EXTRA_LIBS=""

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

have_sync_ref_count=yes
AC_MSG_CHECKING([for __sync_fetch_and_add])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([int x;],
                                   [__sync_fetch_and_add(&x, 1);])],
                  [AC_MSG_RESULT([yes])],
                  [AC_MSG_RESULT([no])
                   have_sync_ref_count=no])
AC_MSG_CHECKING([for __sync_fetch_and_sub])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([int x;],
                                   [__sync_fetch_and_sub(&x, 1);])],
                  [AC_MSG_RESULT([yes])],
                  [AC_MSG_RESULT([no])
                   have_sync_ref_count=no])
AS_IF([test "x$have_sync_ref_count" = "xyes"],
      [AC_DEFINE([HAVE_SYNC_REF_COUNT], [1],
                 [GCC extensions for atomic ref-counting are available])])

have_clock_gettime=no
AC_CHECK_FUNC([clock_gettime], [have_clock_gettime=yes])
AS_IF([test "x$have_clock_gettime" = "xno"],
      [AC_CHECK_LIB([rt], [clock_gettime],
                    [NOTBIT_EXTRA_LIBS="$NOTBIT_EXTRA_LIBS -lrt"],
                    [clock_gettime required but not found])])

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

PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto])

AC_SUBST(NOTBIT_EXTRA_CFLAGS)
AC_SUBST(NOTBIT_EXTRA_LIBS)

AC_CONFIG_FILES([
        Makefile
        build/Makefile
        doc/Makefile
        src/Makefile
])

AC_OUTPUT
