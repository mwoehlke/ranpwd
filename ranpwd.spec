Summary: A program to generate random passwords
Name: ranpwd
Version: 1.1
Release: 1
License: GPL
Group: Applications/System
Source0: ftp://ftp.kernel.org/pub/software/utils/admin/ranpwd/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
A program to generate random passwords using the in-kernel
cryptographically secure random number generator.

%prep
%setup -q

%build
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
make install INSTALLROOT=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc %{_mandir}/man1/*
%{_bindir}/ranpwd

%doc


%changelog
* Mon Mar 17 2003 H. Peter Anvin <hpa@zytor.com>
- Initial build.
