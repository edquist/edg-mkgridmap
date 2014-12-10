Name:		edg-mkgridmap
Version:	4.0.1
Release:	2%{?dist}
Summary:	A tool to build the grid map-file from VO servers
Group:		Applications/Internet
License:	ASL 2.0
Url:		http://svnweb.cern.ch/world/wsvn/curios/edg-mkgridmap

# svn export http://svn.cern.ch/guest/curios/edg-mkgridmap/tags/v4_0_1 edg-mkgridmap-4.0.1
# tar czf edg-mkgridmap-4.0.1.tar.gz edg-mkgridmap-4.0.1
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

