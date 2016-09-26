PACKAGE = edg-mkgridmap
VERSION = 4.0.4
TMP_DIR = $(PACKAGE)-$(VERSION)
TARBALL = $(PACKAGE)-$(VERSION).tar.gz

####################################################################
# Distribution Makefile
####################################################################

bin_dir  = $(prefix)/usr/sbin
lxc_dir  = $(prefix)/usr/libexec/edg-mkgridmap
doc_dir  = $(prefix)/usr/share/doc/edg-mkgridmap
man5_dir = $(prefix)/usr/share/man/man5
man8_dir = $(prefix)/usr/share/man/man8

SOURCES = \
	Makefile \
	edg-mkgridmap.spec \
	sbin/edg-mkgridmap \
	sbin/edg-mkgridmap.pl \
	doc/edg-mkgridmap.8 \
	doc/edg-mkgridmap.conf.5 \
	AUTHORS \
	LICENSE \
	MAINTAINERS

.PHONY: install clean dist rpm

all: install

####################################################################
# Install
####################################################################

install:
	@echo installing ...
	@mkdir -p $(bin_dir)
	@mkdir -p $(lxc_dir)
	@mkdir -p $(doc_dir)
	@mkdir -p $(man5_dir)
	@mkdir -p $(man8_dir)
	@install -m 0755 sbin/edg-mkgridmap       $(bin_dir)
	@install -m 0755 sbin/edg-mkgridmap.pl    $(lxc_dir)
	@install -m 0644 doc/edg-mkgridmap.8      $(man8_dir)
	@install -m 0644 doc/edg-mkgridmap.conf.5 $(man5_dir)

####################################################################
# Build Distribution
####################################################################

dist:
	@mkdir -p $(TMP_DIR)
	@tar cf - $(SOURCES) | (cd $(TMP_DIR) && tar xfp -)
	@tar --gzip -cf $(TARBALL) $(TMP_DIR)
	@rm -rf $(TMP_DIR)

rpm: dist
	@mkdir -p BUILD RPMS SOURCES SPECS SRPMS
	@rpmbuild --define "_topdir `pwd`" -ta $(TARBALL) 

clean::
	rm -rf $(TARBALL)
