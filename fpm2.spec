Summary: Password manager with GTK3 GUI
Name: fpm2
Version: 0.90.2
Release: 1%{?dist}
License: GPLv2+
Source: http://als.regnet.cz/%{name}/download/%{name}-%{version}.tar.xz
URL: http://als.regnet.cz/fpm2/
BuildRequires: meson
BuildRequires: gcc, desktop-file-utils, gettext
BuildRequires: gtk3-devel, libxml2-devel, nettle-devel

%description
Figaro's Password Manager 2 is a program that allows you to securely store the
passwords using GTK3 interface. Features include:
- Passwords are encrypted with the AES-256-GCM algorithm.
- Copy passwords or usernames to the clipboard/primary selection.
- If the password is for a web site, FPM2 can keep track of the URLs of your
  login screens and can automatically launch your browser. In this capacity,
  FPM2 acts as a kind of bookmark manager.
- Combine all three features: you can configure FPM2 to bring you to a web
  login screen, copy your username to the clipboard and your password to the
  primary selection, all with a single button click.
- FPM2 also has a password generator that can choose passwords for you. It
  allows you to determine how long the password should be, and what types of
  characters (lower case, upper case, numbers and symbols) should be used.
  You can even have it avoid ambiguous characters such as a capital O or the
  number zero.
- Auto-minimise and/or auto-locking passwords database after configurable time
  to the tray icon.

%prep
%autosetup

%conf
%meson

%build
%meson_build

%install
%meson_install

%find_lang %{name}

desktop-file-install \
  --delete-original \
  --dir %{buildroot}%{_datadir}/applications \
  %{buildroot}%{_datadir}/applications/%{name}.desktop

%files -f %{name}.lang
%doc AUTHORS COPYING ChangeLog NEWS README TODO
%{_bindir}/fpm2
%{_datadir}/pixmaps/fpm2
%{_mandir}/man1/fpm2.1.gz
%{_datadir}/applications/fpm2.desktop
%{_datadir}/icons/hicolor/*/apps/fpm2.png
%{_datadir}/metainfo/fpm2.metainfo.xml

%check
# No tests available for this package

%changelog
* Fri Oct 31 2025 Aleš Koval <als@regnet.cz> - 0.90.2-1
- Update to 0.90.2
- Change build system from GNU Autotools to Meson

* Tue Feb 25 2025 Aleš Koval <als@regnet.cz> - 0.90.1-1
- Update to 0.90.1
- Fix FTBFS (#2340169)

* Thu Feb 13 2020 Aleš Koval <als@regnet.cz> - 0.90-1
- Update to 0.90

* Thu Oct 17 2019 Aleš Koval <als@regnet.cz> - 0.79-21
- Build for EPEL-8

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-20
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-19
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-18
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Wed Mar 07 2018 Aleš Koval <als@regnet.cz> - 0.79-17
- Add gcc to BuildRequires:

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-16
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-15
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-14
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-13
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 0.79-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Fri Mar 15 2013 Jon Ciesla <limburgher@gmail.com> - 0.79-7
- Drop desktop vendor tag.

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Thu Jul 19 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Tue Dec 06 2011 Adam Jackson <ajax@redhat.com> - 0.79-3
- Rebuild for new libpng

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.79-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Mon Jan 17 2011 Aleš Koval <als@regnet.cz> - 0.79-1
- Update to 0.79
- Fixed crash due to incorrectly call xmlCleanupParser() (#669102)

* Wed Mar  3 2010 Aleš Koval <als@regnet.cz> - 0.78-1
- Update to 0.78
- Fixed crash in master password dialog after open keyfile (#569520)

* Tue Feb 23 2010 Aleš Koval <als@regnet.cz> - 0.77-1
- Update to 0.77
- Fix ImplicitDSOLinking (#565058)

* Mon Nov  9 2009 Aleš Koval <als@regnet.cz> - 0.76.1-1
- Update to 0.76.1

* Fri Nov  6 2009 Aleš Koval <als@regnet.cz> - 0.76-1
- Update to 0.76

* Tue Apr  7 2009 Christoph J. Thompson <cjsthompson@gmail.com>
- Pixmaps are now in /usr/share/pixmaps/fpm2

* Mon Mar  2 2009 Aleš Koval <als@regnet.cz> - 0.75-1
- Update to 0.75

* Mon Jul  7 2008 Aleš Koval <als@regnet.cz> - 0.72-1
- Update to 0.72

* Thu May  8 2008 Aleš Koval <als@regnet.cz> - 0.71-2
- Fix %%files section (#444830)
- desktop-file-install now delete original .desktop file

* Wed Apr 30 2008 Aleš Koval <als@regnet.cz> - 0.71-1
- Initial build.
