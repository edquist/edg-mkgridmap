Name:		edg-mkgridmap
Version:	4.0.4
Release:	1%{?dist}
Summary:	A tool to build the grid map-file from VO servers
Group:		Applications/Internet
License:	ASL 2.0
Url:		http://svnweb.cern.ch/world/wsvn/curios/edg-mkgridmap

# svn export http://svn.cern.ch/guest/curios/edg-mkgridmap/tags/v4_0_4 edg-mkgridmap-4.0.4
# tar czf edg-mkgridmap-4.0.4.tar.gz edg-mkgridmap-4.0.4
Source0:	%{name}-%{version}.tar.gz

Buildroot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:	noarch

Requires:	perl(URI)
Requires:	perl(Net::LDAP)
Requires:	perl(Net::LDAPS)
Requires:	perl(Term::ReadKey)
Requires:	perl(IO::Socket::SSL) >= 0.90
Requires:	perl(Net::SSLeay) >= 1.16
Requires:	perl(Crypt::SSLeay)
Requires:	perl(LWP)
Requires:	perl(XML::DOM)
Requires:	perl(Date::Manip)
Requires:       perl(LWP::Protocol::https)

%description
edg-mkgridmap is a tool to build the grid map-file from VO servers,
taking into account both VO and local policies.

%prep
%setup -q -n %{name}-%{version}

%build

%install
rm -rf %{buildroot}
make install prefix=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc AUTHORS LICENSE MAINTAINERS
%dir %{_libexecdir}/edg-mkgridmap
%{_libexecdir}/edg-mkgridmap/edg-mkgridmap.pl
%{_sbindir}/edg-mkgridmap
%{_mandir}/man5/edg-mkgridmap.conf.5*
%{_mandir}/man8/edg-mkgridmap.8*

%changelog
* Mon Sep 26 2016 <Maarten.Litmaath@cern.ch> - 4.0.4-1
- Fixed omission that caused fatal errors on CentOS 7 but not on SL6.

* Wed Jul 29 2015 <Maarten.Litmaath@cern.ch> - 4.0.3-1
- Mainly adaptations to changes in underlying libraries on CentOS/EL7.

* Wed Apr 29 2015 <Maarten.Litmaath@cern.ch> - 4.0.2-1
- Do not crash on empty user records, just ignore them (GGUS ticket 113371).

* Sun Nov 30 2014 <Maarten.Litmaath@cern.ch> - 4.0.1-1
- No longer require SSLv3, allow TLS to be negotiated instead.
- Relocation of source repository.
- Cleanup for EPEL builds.

* Fri Nov 21 2014 Alejandro Alvarez Ayllon <aalvarez@cern.ch> - 4.0.0-8
- Added Requires perl(LWP::Protocol::https)

* Thu May 23 2013 <aalvarez@cern.ch> - 4.0.0-4
- Added dist to the release number.

* Wed May 08 2013 <aalvarez@cern.ch> - 4.0.0-3
- Marking libexec/edg-mkgridmap as owned

* Mon Apr 29 2013 <aalvarez@cern.ch> - 4.0.0-2
- Preparing for release in Fedora/EPEL

* Sun Apr  3 2011 <Maarten.Litmaath@cern.ch> - 4.0.0-1
- Adaptations for EMI.
- Removed obsolete components.
- Version 4.0.0

