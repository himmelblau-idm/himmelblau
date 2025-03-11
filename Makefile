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

deb: .packaging .submodules
	for v in ubuntu22.04 ubuntu24.04 debian12; do \
		echo "Building Ubuntu $$v packages"; \
		$(DOCKER) build -t himmelblau-$$v-build -f images/deb/Dockerfile.$$v .; \
		$(DOCKER) run --rm --security-opt label=disable -it -v ./:/himmelblau himmelblau-$$v-build; \
		mv ./target/debian/*.deb ./packaging/; \
	done

rpm: .packaging .submodules
	for v in rocky8 rocky9 sle15sp6 tumbleweed rawhide fedora41; do \
		echo "Building $$v RPM packages"; \
		$(DOCKER) build -t himmelblau-$$v-build -f images/rpm/Dockerfile.$$v .; \
		$(DOCKER) run --rm --security-opt label=disable -it -v ./:/himmelblau himmelblau-$$v-build; \
		for file in ./target/generate-rpm/*.rpm; do \
			mv "$$file" "$${file%.rpm}-$$v.rpm"; \
		done; \
		mv ./target/generate-rpm/*.rpm ./packaging/; \
	done

nix: .packaging .submodules
	echo "Building nix packages"
	for v in himmelblau himmelblau-desktop; do \
		$(NIX) --extra-experimental-features 'nix-command flakes' build ".#$$v" --out-link ./packaging/nix-$$v-result; \
	done

package: deb rpm nix
	ls ./packaging/
