srpm:
	dnf install -y rpmdevtools
	spectool --define '_srcrpmdir $(outdir)' -C $(outdir) -g ducky-qemu.spec
	rpmbuild -bs --define '_sourcedir $(outdir)' --define '_srcrpmdir $(outdir)' ducky-qemu.spec
