ACLOCAL_AMFLAGS = -I m4

plugin_LTLIBRARIES = arachne.la
arachne_la_CXXFLAGS = -g -std=c++11 -I/usr/include/dbus-c++-1/
arachne_la_LDFLAGS = -module -avoid-version -shared
arachne_la_LIBADD = -lboost_system -ldbus-c++-1
arachne_la_SOURCES =  FirewallD1.cpp FirewallD1_Config.cpp FirewallD1_Zone.cpp \
	FirewallD1_Config_Zone.cpp \
	ArachnePlugin.cpp Url.cpp ClientSession.cpp \
	IniFile.cpp IniFileException.cpp Firewall.cpp \
	main.cpp

EXTRA_DIST= \
<<<<<<< HEAD
	ArachnePlugin.h Url.h ClientSession.h FirewallD1.h \
	FirewallD1_Config_Zone.xml

BUILT_SOURCES = FirewallD1_proxy.h FirewallD1_Config_proxy.h \
	FirewallD1_Config_Zone_proxy.h

FirewallD1.xml:
	dbusxx-introspect --system \
		/org/fedoraproject/FirewallD1 \
		org.fedoraproject.FirewallD1 \
		> FirewallD1.xml

FirewallD1_Config.xml:
	dbusxx-introspect --system \
		/org/fedoraproject/FirewallD1/config \
		org.fedoraproject.FirewallD1 \
		> FirewallD1_Config.xml

FirewallD1_proxy.h: FirewallD1.xml
	dbusxx-xml2cpp $^ --proxy=$@

FirewallD1_Config_proxy.h: FirewallD1_Config.xml
	dbusxx-xml2cpp $^ --proxy=$@

FirewallD1_Config_Zone_proxy.h: FirewallD1_Config_Zone.xml
	dbusxx-xml2cpp $^ --proxy=$@
	sed -i 's/const bool default/const bool idDefault/g' $@
	sed -i 's/\& short/\& s/g' $@
	sed -i 's/<< short/<< s/g' $@

clean-local:
	rm -v *h *xml
=======
	ArachnePlugin.h Url.h ClientSession.h IniFile.h

>>>>>>> 8d7bbf07646e3b59f4122a01de9818e7e0b13d96
