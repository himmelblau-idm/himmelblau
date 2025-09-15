all:
	git submodule init; git submodule update
	cargo build --release

build-tests:
	$(MAKE) -C tests

test: build-tests
	$(MAKE) -C tests test

clean:
	cargo clean
	$(MAKE) -C tests clean

PLATFORM := $(shell grep '^ID=' /etc/os-release | awk -F= '{ print $$2 }' | tr -d '"')

install-opensuse:
	install -D -d -m 0755 /etc/himmelblau
	install -m 0644 ./src/config/himmelblau.conf.example /etc/himmelblau/himmelblau.conf
	install -m 0755 ./target/release/libnss_himmelblau.so /usr/lib64/libnss_himmelblau.so.2
	install -m 0755 ./target/release/libpam_himmelblau.so /usr/lib64/security/pam_himmelblau.so
	install -m 0755 ./target/release/himmelblaud /usr/sbin
	install -m 0755 ./target/release/himmelblaud_tasks /usr/sbin
	install -m 0755 ./target/release/aad-tool /usr/bin
	install -m 0644 ./platform/opensuse/himmelblaud.service /usr/lib/systemd/system
	install -m 0644 ./platform/opensuse/himmelblaud-tasks.service /usr/lib/systemd/system

install-ubuntu:
	install -D -d -m 0755 /etc/himmelblau
	install -m 0644 ./src/config/himmelblau.conf.example /etc/himmelblau/himmelblau.conf
	install -m 0755 ./target/release/libnss_himmelblau.so /usr/lib/x86_64-linux-gnu/libnss_himmelblau.so.2
	install -m 0755 ./target/release/libpam_himmelblau.so /usr/lib/x86_64-linux-gnu/security/pam_himmelblau.so
	if [ -d "/usr/lib/security" ]; then \
		ln -s /usr/lib/x86_64-linux-gnu/security/pam_himmelblau.so /usr/lib/security/pam_himmelblau.so; \
	fi
	install -m 0644 ./platform/debian/pam-config /usr/share/pam-configs/himmelblau
	install -m 0755 ./target/release/himmelblaud /usr/sbin
	install -m 0755 ./target/release/himmelblaud_tasks /usr/sbin
	install -m 0755 ./target/release/aad-tool /usr/bin
	install -m 0644 ./platform/debian/himmelblaud.service /etc/systemd/system
	install -m 0644 ./platform/debian/himmelblaud-tasks.service /etc/systemd/system
	if [ -d "/etc/ssh/sshd_config.d" ]; then \
		install -m 0644 ./platform/debian/sshd_config /etc/ssh/sshd_config.d/himmelblau.conf; \
	fi

install:
ifeq ($(PLATFORM), debian)
	$(MAKE) install-ubuntu
else ifeq ($(PLATFORM), ubuntu)
	$(MAKE) install-ubuntu
else ifneq (,$(findstring opensuse,$(PLATFORM)))
	$(MAKE) install-opensuse
else
	$(error "Unsupported platform: $(PLATFORM)")
endif

DOCKER := $(shell command -v podman || command -v docker)
NIX := $(shell command -v nix)

.submodules:
	git submodule init; git submodule update

.packaging:
	mkdir -p ./packaging/

nix: .packaging .submodules
	echo "Building nix packages"
	for v in himmelblau himmelblau-desktop; do \
		$(NIX) --extra-experimental-features 'nix-command flakes' build ".#$$v" --out-link ./packaging/nix-$$v-result; \
	done

DEB_TARGETS := ubuntu22.04 ubuntu24.04 debian12
RPM_TARGETS := rocky8 rocky9 rocky10 sle15sp6 tumbleweed rawhide fedora41 fedora42
SLE_TARGETS := sle15sp7

.PHONY: package deb rpm $(DEB_TARGETS) $(RPM_TARGETS) ${SLE_TARGETS}

package: deb rpm
	ls ./packaging/

deb: $(DEB_TARGETS)

GPG_KEY_RSA_EL8   := 0xFFE471BA97CD96ED7330E0B4F5A25D2D6AA97EC9
GPG_KEY_ED25519   := 0x3D46C88168B2FF8D75D0B1786CCA48F23916FC03
rpm: $(RPM_TARGETS) $(SLE_TARGETS) sign-rpms

# Sign EL8/SLE15 with RSA (older rpm doesn’t support Ed25519)
sign-el8-sle:
	@set -e; shopt -s nullglob; \
	el8_sle_pkgs=(./packaging/*rocky8*.rpm); \
	if [ $${#el8_sle_pkgs[@]} -gt 0 ]; then \
	  echo "Signing EL8 with $(GPG_KEY_RSA_EL8)"; \
	  rpmsign --define "_gpg_name $(GPG_KEY_RSA_EL8)" --addsign "$${el8_sle_pkgs[@]}"; \
	else \
	  echo "No EL8 RPMs to sign."; \
	fi

# Sign everything else with Ed25519
sign-others:
	@set -e; shopt -s nullglob; \
	all=(./packaging/*.rpm); \
	excl=(./packaging/*rocky8*.rpm); \
	sign_list=(); \
	for f in "$${all[@]}"; do \
	  skip=0; for e in "$${excl[@]}"; do [[ "$$f" == "$$e" ]] && skip=1 && break; done; \
	  [ $$skip -eq 0 ] && sign_list+=("$$f"); \
	done; \
	if [ $${#sign_list[@]} -gt 0 ]; then \
	  echo "Signing non-EL8 with $(GPG_KEY_ED25519)"; \
	  rpmsign --define "_gpg_name $(GPG_KEY_ED25519)" --addsign "$${sign_list[@]}"; \
	else \
	  echo "No non-EL8 RPMs to sign."; \
	fi

sign-rpms: sign-el8-sle sign-others

$(DEB_TARGETS): %: .packaging .submodules
	@echo "Building Ubuntu $@ packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/deb/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	mv ./target/$@/debian/*.deb ./packaging/

$(RPM_TARGETS): %: .packaging .submodules
	@echo "Building $@ RPM packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/rpm/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	for file in ./target/$@/generate-rpm/*.rpm; do \
		mv "$$file" "$${file%.rpm}-$@.rpm"; \
	done
	mv ./target/$@/generate-rpm/*.rpm ./packaging/

$(SLE_TARGETS): %: .packaging .submodules
	@echo "Building $@ RPM packages"
	mkdir -p target/$@
	$(DOCKER) build --secret id=scc_regcode,src=${HOME}/.secrets/scc_regcode -t himmelblau-$@-build -f images/rpm/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	for file in ./target/$@/generate-rpm/*.rpm; do \
		mv "$$file" "$${file%.rpm}-$@.rpm"; \
	done
	mv ./target/$@/generate-rpm/*.rpm ./packaging/
