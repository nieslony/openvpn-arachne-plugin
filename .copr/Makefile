current_dir := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
mkdist_dir := $(current_dir)/mk-dist

srpm:
	dnf -y install autoconf automake autoconf-archive libtool gcc-c++ boost-devel sdbus-cpp-devel
	( cd $(current_dir)/.. ; ./gen-auto.sh )
	mkdir -pv $(mkdist_dir)
	( cd $(mkdist_dir) ; ../../configure ; make dist )
	rpmbuild -bs \
		--define "_sourcedir $(mkdist_dir)" \
		--define "_srcrpmdir $(outdir)" \
		$(mkdist_dir)/openvpn-plugin-arachne.spec
	cp -v $(mkdist_dir)/openvpn-plugin-arachne.spec $(spec)
