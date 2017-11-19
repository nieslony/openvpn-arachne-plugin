Name:       openvpn-arachne-plugin
Version:    0.1.0
Release:    1
Summary:    openVPN plugin needed by arachne

License:    GPL-2.0+
URL:        http://www.nieslony.site/arachne
Source0:    %{name}-%{version}.tar.gz
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  openvpn-devel, boost-devel, gcc-c++

%if 0%{?centos_version}
%define cxxflags --std=c++11
%endif
%if 0%{?fedora_version}
%define cxxflags ""
%endif
%if 0%{?suse_version}
%define cxxflags --std=c++11
%define _pkgdocdir /usr/share/doc/packages/%{name}
%endif

%description
openVPN plugin needed by arachne
 - authentication via HTTP(S) url

%prep
%setup -q

%build
CXXFLAGS=%{cxxflags} ./configure --libdir=%{_libdir}
%{__make}

%install
%{__make} install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' | xargs rm -f
mkdir -pv $RPM_BUILD_ROOT%{_pkgdocdir}
cp -a LICENSE $RPM_BUILD_ROOT%{_pkgdocdir}

%files
%{_pkgdocdir}
%{_libdir}/openvpn

%changelog
* Sun Nov 19 2017 Claas Nieslony <claas@nieslony.at> 0.1.0
- Initial version
