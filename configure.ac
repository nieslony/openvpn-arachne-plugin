AC_INIT([arachne], [1.0], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_VAR([PLUGINDIR], [Path of plug-in directory @<:@default=LIBDIR/openvpn/plugins@:>@])
if test -n "${PLUGINDIR}"; then
        plugindir="${PLUGINDIR}"
else
        plugindir="\${libdir}/openvpn/plugins"
fi

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR
AM_PROG_LD
LT_INIT([disable-static])

AC_CHECK_HEADER(openvpn-plugin.h)
AC_CHECK_HEADER(boost/asio.hpp)

AC_SUBST([plugindir])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
