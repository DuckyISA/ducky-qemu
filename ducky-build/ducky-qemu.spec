%global source_version 2.11.92-1

# disable check-buildroot - buildroot is mentioned in binaries, some __FILE__ or what?
%define __arch_install_post %{nil}

# disable debug package, otherwise error: Empty %files file …/debugfiles.list
%define debug_package %{nil}

Name:	    ducky-qemu
Version:	2.11.92
Release:	1%{?dist}
Summary:	QEMU is a generic and open source machine & userspace emulator and virtualizer. Ducky VM support.

License:	QEMU license
URL:		https://github.com/happz/ducky-qemu
Source0:  http://fanny.happz.cz/~happz/ducky-dist/ducky-qemu-%{source_version}.tar.bz2

BuildRequires:  glib2-devel
BuildRequires:  make
BuildRequires:  pixman-devel
BuildRequires:  python2
BuildRequires:  zlib-devel

%description
QEMU is a generic and open source machine & userspace emulator and virtualizer.

This build of QEMU is patched to run Ducky binaries.

%prep
%autosetup -n ducky-qemu-%{source_version}

%build
mkdir -p _build
cd _build

../configure --disable-user \
             --target-list=ducky-softmmu \
             --prefix=%{buildroot}/opt/ducky

make %{?_smp_mflags}

%install
cd _build
make install

%files
/opt/ducky/bin/*
/opt/ducky/libexec/*
/opt/ducky/share/*
/opt/ducky/var/run

%changelog
