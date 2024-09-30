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
	install -m 0755 ./target/release/libpam_himmelblau.so /usr/lib64/security
	install -m 0755 ./target/release/himmelblaud /usr/sbin
	install -m 0755 ./target/release/himmelblaud_tasks /usr/sbin
	install -m 0755 ./target/release/aad-tool /usr/bin
	install -m 0644 ./platform/opensuse/himmelblaud.service /usr/lib/systemd/system
	install -m 0644 ./platform/opensuse/himmelblaud-tasks.service /usr/lib/systemd/system

install-debian:
	install -D -d -m 0755 /etc/himmelblau
	install -m 0644 ./src/config/himmelblau.conf.example /etc/himmelblau/himmelblau.conf
	install -m 0755 ./target/release/libnss_himmelblau.so /usr/lib/x86_64-linux-gnu/libnss_himmelblau.so.2
	install -m 0755 ./target/release/libpam_himmelblau.so /usr/lib/x86_64-linux-gnu
	install -m 0755 ./target/release/himmelblaud /usr/sbin
	install -m 0755 ./target/release/himmelblaud_tasks /usr/sbin
	install -m 0755 ./target/release/aad-tool /usr/bin
	install -m 0644 ./platform/debian/himmelblaud.service /usr/lib/systemd/system
	install -m 0644 ./platform/debian/himmelblaud-tasks.service /usr/lib/systemd/system

install:
ifeq ($(PLATFORM), debian)
	$(MAKE) install-debian
else ifeq ($(PLATFORM), ubuntu)
	$(MAKE) install-ubuntu
else ifneq (,$(findstring opensuse,$(PLATFORM)))
	$(MAKE) install-opensuse
else
	$(error "Unsupported platform: $(PLATFORM)")
endif
