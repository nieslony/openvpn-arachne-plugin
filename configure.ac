AC_INIT([openvpn-plugin-arachne], [0.1.2_git], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign tar-pax])

AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_VAR([PLUGINDIR], [Path of plug-in directory @<:@default=LIBDIR/openvpn/plugins@:>@])
if test -n "${PLUGINDIR}"; then
        plugindir="${PLUGINDIR}"
else
        plugindir="\${libdir}/openvpn/plugins"
fi

AC_PROG_CXX
AM_PROG_AR
AM_PROG_LD
LT_INIT([disable-static])

AX_CXX_COMPILE_STDCXX(20, [noext], [mandatory])

AC_CHECK_HEADERS([openvpn-plugin.h openvpn/openvpn-plugin.h])
AX_BOOST_BASE
AX_BOOST_SYSTEM
AX_BOOST_REGEX

PKG_CHECK_MODULES(SDBUSCPP, [sdbus-c++ >= 1.0],,
    AC_MSG_ERROR([You need the sdbus-c++ library (version 1.0 or newer)]
    [http://www.kistler.com/])
)

AC_CHECK_TOOL(XMLSTARLET, xmlstarlet)
AS_IF([test x"$XMLSTARLET" = x""], [AC_MSG_ERROR([Please install xmlstarlet $XMLSTARLET])])

AC_SUBST([plugindir])

AC_CONFIG_FILES([
    Makefile
    openvpn-plugin-arachne.spec
    src/Makefile
])
AC_OUTPUT
