AC_INIT([openvpn-arachne-plugin], [0.1.1a_git], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign tar-pax])

AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_VAR([PLUGINDIR], [Path of plug-in directory @<:@default=LIBDIR/openvpn/plugins@:>@])
if test -n "${PLUGINDIR}"; then
        plugindir="${PLUGINDIR}"
else
        plugindir="\${libdir}/openvpn/plugins"
fi

# AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR
AM_PROG_LD
AX_CXX_COMPILE_STDCXX_11
LT_INIT([disable-static])

AC_CHECK_HEADERS([openvpn-plugin.h openvpn/openvpn-plugin.h])
AC_CHECK_HEADERS(boost/algorithm/string.hpp)

AC_SUBST([plugindir])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
