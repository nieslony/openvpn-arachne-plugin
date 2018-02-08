AC_INIT([openvpn-arachne-plugin], [0.1.1git], [bug-automake@gnu.org])
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

AC_CHECK_HEADERS([openvpn-plugin.h openvpn/openvpn-plugin.h])
AC_CHECK_HEADER(boost/asio.hpp)
AC_CHECK_HEADER(boost/bind.hpp)
AC_CHECK_HEADER(boost/asio/ssl.hpp)
AC_CHECK_HEADER(dbus-cxx.h)

AC_SUBST([plugindir])

AC_CONFIG_FILES([
    Makefile
    openvpn-arachne-plugin.spec
    src/Makefile
    debian/debian.control
    debian/debian.rules
    debian/debian.changelog
    debian/openvpn-arachne-plugin.dsc
])
AC_OUTPUT
