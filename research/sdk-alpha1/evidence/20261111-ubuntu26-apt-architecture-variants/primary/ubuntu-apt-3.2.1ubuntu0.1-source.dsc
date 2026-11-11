-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (native)
Source: apt
Binary: apt, libapt-pkg7.0, apt-doc, libapt-pkg-dev, libapt-pkg-doc, apt-utils, apt-transport-https
Architecture: any all
Version: 3.2.1ubuntu0.1
Maintainer: APT Development Team <deity@lists.debian.org>
Uploaders: Michael Vogt <mvo@debian.org>, Julian Andres Klode <jak@debian.org>, David Kalnischkies <donkult@debian.org>
Standards-Version: 4.1.1
Vcs-Browser: https://salsa.debian.org/apt-team/apt
Vcs-Git: https://salsa.debian.org/apt-team/apt.git
Testsuite: autopkgtest
Testsuite-Triggers: @builddeps@, aptitude, db-util, dpkg, expect, fakeroot, g++, gdb, gpgv, gpgv-sq, jq, libfile-fcntllock-perl, lsof, moreutils, pkg-config, python3-apt, sq, sqv, stunnel4, valgrind-if-available, wget
Build-Depends: dpkg-dev (>= 1.22.5) <!pkg.apt.ci>, cmake (>= 3.4), debhelper-compat (= 12), docbook-xml <!nodoc>, docbook-xsl <!nodoc>, dpkg-dev (>= 1.20.8), gettext (>= 0.12), googletest <!nocheck> | libgtest-dev <!nocheck>, libbz2-dev, libdb-dev, libssl-dev, liblz4-dev (>= 0.0~r126), liblzma-dev, libseccomp-dev (>= 2.4.2) [amd64 arm64 armel armhf i386 mips mips64el mipsel ppc64el s390x hppa powerpc powerpcspe ppc64 x32], libsystemd-dev [linux-any], libudev-dev [linux-any], libxxhash-dev (>= 0.8), libzstd-dev (>= 1.0), ninja-build, pkg-config, po4a (>= 0.34-2) <!nodoc>, sqv (>= 1.3.0) [amd64 arm64 armel armhf i386 mips64el ppc64el riscv64 s390x hurd-amd64 hurd-i386 loong64 powerpc ppc64 sparc64] <!pkg.apt.nosqv> | gpgv, triehash, xsltproc <!nodoc>, zlib1g-dev
Build-Depends-Indep: doxygen <!nodoc !pkg.apt.nodoxygen>, graphviz <!nodoc !pkg.apt.nodoxygen>, w3m <!nodoc>
Package-List:
 apt deb admin required arch=any
 apt-doc deb doc optional arch=all profile=!nodoc profile:v1=!nodoc
 apt-transport-https deb oldlibs optional arch=all
 apt-utils deb admin required arch=any
 libapt-pkg-dev deb libdevel optional arch=any
 libapt-pkg-doc deb doc optional arch=all profile=!nodoc profile:v1=!nodoc
 libapt-pkg7.0 deb libs optional arch=any
Checksums-Sha1:
 a680398b1879917b68a9c833169540bf4d77995f 2477440 apt_3.2.1ubuntu0.1.tar.xz
Checksums-Sha256:
 0febcf286d6038c534c4aa83119dbf8a4dda29a10e133ca97adb01b368d420cc 2477440 apt_3.2.1ubuntu0.1.tar.xz
Files:
 edcaac5c907f8a8cb0a9c940e0eba478 2477440 apt_3.2.1ubuntu0.1.tar.xz

-----BEGIN PGP SIGNATURE-----

iQJHBAEBCgAxFiEET7WIqEwt3nmnTHeHb6RY3R2wP3EFAmro01UTHGp1bGlhbmtA
dWJ1bnR1LmNvbQAKCRBvpFjdHbA/cQ5pEACIq/9WDhUwvE9yQO0KoPwMGoZIkuTN
m5lQSjQG4XQU9MNy9pmKpwKKJYolY/K8O09DQDODNJyzSd6m41kdv7FBCfmHwJHo
sQgf/t8TH5LAZQbKJEnsuhDc4IG1MctaZn3ueLkdG33fVJOR7kkpYDLufvyYZLGa
3p0bpir3+PaaSXgzGlv3i+iT/v7OfKYpXyvwMCwRr/S49qgu59jf50SaUlJVQaHt
dA4PZw8mCDbwuicWygHy6QhiMixgEG5Il6TkYhzePlQsMs//BzajIvj6bQ2SJLMQ
ns5rPXKUjQOvrkQK63yep9NquKA8yfxv11vssR8/CcCghRtHREblVVxb6fdESKqM
pjP/t4XFNZXV5+Ag3GGnZ9eEp5/CA0gVBqN9s+TcUvLi0CujtuEfciVH5sdYkIJr
lagc7EQPDXRIkBeMVlpQZYGMlTutwLcROiOba//2QcNIa1kxCiKLhF4vHAHPyj2T
4IIras8gV4qDpwfam31PTZszZxkUJdijsPau0o+bTE+FmxvX055R37T2sGwtF4e4
ggTlDrlw7YVpf5DtP+lA1vMhIkVl2UVMAnRdHygqUgnFf+oyBNuVYDUd3eDXSBcp
F5O+lZTAPrbaZcdTto4B6qzY/p2Jgb7i1kIlvH9FA3vVjJhYsvAEDkJl2yE3LIRs
kbHZD1UulT40Iw==
=I9id
-----END PGP SIGNATURE-----
