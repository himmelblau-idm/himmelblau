all: .packaging dockerfiles
	@set -euo pipefail; \
	source /etc/os-release; \
	ID="$${ID}"; VER="$${VERSION_ID}"; LIKE="$${ID_LIKE:-}"; \
	TARGET=""; \
	echo "Detecting host distro: ID=$$ID VERSION_ID=$$VER ID_LIKE=$$LIKE"; \
	case "$$ID" in \
	  ubuntu)         case "$$VER" in 22.04*) TARGET="ubuntu22.04" ;; 24.04*) TARGET="ubuntu24.04" ;; esac ;; \
	  linuxmint)      case "$$VER" in 21.*)   TARGET="ubuntu22.04" ;; 22*|23*) TARGET="ubuntu24.04" ;; esac ;; \
	  debian)         case "$$VER" in 12*|12.*) TARGET="debian12" ;; 13*|13.*) TARGET="debian13" ;; esac ;; \
	  rocky|almalinux|rhel|ol|oraclelinux|centos|centos_stream|centos-stream) \
		major=$$(echo "$$VER" | awk -F. '{print $$1}'); \
		case "$$major" in 8) TARGET="rocky8" ;; 9) TARGET="rocky9" ;; 10) TARGET="rocky10" ;; esac ;; \
	  fedora)         case "$$VER" in 41*) TARGET="fedora41" ;; 42*) TARGET="fedora42" ;; *) TARGET="rawhide" ;; esac ;; \
	  sles|sled|sle_micro|suse|suse-linux-enterprise) \
		case "$$VER" in 15.6*|15-SP6*) TARGET="sle15sp6" ;; 15.7*|15-SP7*) TARGET="sle15sp7" ;; 16*|16.*) TARGET="sle16" ;; esac ;; \
	  opensuse-leap)  case "$$VER" in 15.6*) TARGET="sle15sp6" ;; 15.7*) TARGET="sle15sp7" ;; esac ;; \
	  opensuse-tumbleweed) TARGET="tumbleweed" ;; \
	esac; \
	if [ -z "$$TARGET" ]; then echo "Error: unsupported or unmapped distro: $$ID $$VER"; exit 2; fi; \
	all_targets="$(ALL_PACKAGE_TARGETS)"; \
	case " $${all_targets} " in *" $$TARGET "*) ;; \
	  *) echo "Error: no packaging rule for '$$TARGET' (supported: $${all_targets})"; exit 3 ;; esac; \
	echo "Building packages for target '$$TARGET'…"; \
	$(MAKE) $$TARGET; \
	echo "Packages written to ./packaging/"

build-tests:
	$(MAKE) -C tests

test: build-tests
	$(MAKE) -C tests test

clean:
	cargo clean
	$(MAKE) -C tests clean

PLATFORM := $(shell grep '^ID=' /etc/os-release | awk -F= '{ print $$2 }' | tr -d '"')

DOCKER := $(shell command -v podman || command -v docker)
NIX := $(shell command -v nix)

.packaging:
	mkdir -p ./packaging/

nix: .packaging
	echo "Building nix packages"
	for v in himmelblau himmelblau-desktop; do \
		$(NIX) --extra-experimental-features 'nix-command flakes' build ".#$$v" --out-link ./packaging/nix-$$v-result; \
	done

DEB_TARGETS := ubuntu22.04 ubuntu24.04 debian12 debian13
RPM_TARGETS := rocky8 rocky9 rocky10 tumbleweed rawhide fedora41 fedora42
SLE_TARGETS := sle15sp6 sle15sp7 sle16
ALL_PACKAGE_TARGETS := $(DEB_TARGETS) $(RPM_TARGETS) $(SLE_TARGETS)

install:
	@set -euo pipefail; \
	source /etc/os-release; \
	ID="$${ID}"; VER="$${VERSION_ID}"; \
	PKGTYPE=""; RPM_SUFFIX=""; INSTALL_CMD=""; \
	case "$$ID" in \
	  ubuntu|linuxmint|debian) \
		PKGTYPE="deb"; INSTALL_CMD='apt-get update && apt-get install -y ./packaging/*.deb' ;; \
	  rocky|almalinux|rhel|ol|oraclelinux|centos|centos_stream|centos-stream|fedora|sles|sled|sle_micro|suse|suse-linux-enterprise|opensuse-leap|opensuse-tumbleweed) \
		PKGTYPE="rpm"; INSTALL_CMD='(command -v dnf >/dev/null && dnf -y install ./packaging/*.rpm) || \
		                            (command -v yum >/dev/null && yum -y localinstall ./packaging/*.rpm) || \
		                            (command -v zypper >/dev/null && zypper --non-interactive --no-gpg-checks in ./packaging/*.rpm)';; \
	esac; \
	if [ -z "$$PKGTYPE" ]; then echo "Error: unknown distro family for install"; exit 2; fi; \
	if [ "$$PKGTYPE" = "deb" ]; then \
	  ls ./packaging/*.deb >/dev/null 2>&1 || { echo "Error: no .deb packages in ./packaging/ — run 'make' first"; exit 4; }; \
	else \
	  ls ./packaging/*.rpm >/dev/null 2>&1 || { echo "Error: no .rpm packages in ./packaging/ — run 'make' first"; exit 4; }; \
	fi; \
	echo "Installing from ./packaging/…"; \
	sh -c "$$INSTALL_CMD"; \
	echo "Install complete."

dockerfiles:
	python3 scripts/gen_dockerfiles.py --out ./images/

.PHONY: package deb rpm $(DEB_TARGETS) $(RPM_TARGETS) ${SLE_TARGETS} dockerfiles

package: deb rpm
	ls ./packaging/

deb: $(DEB_TARGETS)

rpm: $(RPM_TARGETS) $(SLE_TARGETS)
	rpmsign --addsign ./packaging/*.rpm

$(DEB_TARGETS): %: .packaging dockerfiles
	@echo "Building Ubuntu $@ packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	mv ./target/$@/debian/*.deb ./packaging/

$(RPM_TARGETS): %: .packaging dockerfiles
	@echo "Building $@ RPM packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	for file in ./target/$@/generate-rpm/*.rpm; do \
		mv "$$file" "$${file%.rpm}-$@.rpm"; \
	done
	mv ./target/$@/generate-rpm/*.rpm ./packaging/

$(SLE_TARGETS): %: .packaging dockerfiles
	@echo "Building $@ SLE RPM packages"
	mkdir -p target/$@
	$(DOCKER) build --secret id=scc_regcode,src=${HOME}/.secrets/scc_regcode -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	for file in ./target/$@/generate-rpm/*.rpm; do \
		mv "$$file" "$${file%.rpm}-$@.rpm"; \
	done
	mv ./target/$@/generate-rpm/*.rpm ./packaging/
