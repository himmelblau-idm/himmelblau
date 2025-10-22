all: .packaging dockerfiles ## Auto-detect host distro and build packages just for this host
	@set -euo pipefail; \
	. /etc/os-release; \
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

test: dockerfiles ## Run cargo tests in a container
	mkdir -p target/test
	$(DOCKER) build -t himmelblau-test-build -f images/Dockerfile.test .
	$(DOCKER) run --rm --security-opt label=disable -it \
                -v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/test:/himmelblau/target \
                himmelblau-test-build

clean: ## Remove cargo build artifacts
	cargo clean

PLATFORM := $(shell grep '^ID=' /etc/os-release | awk -F= '{ print $$2 }' | tr -d '"')

DOCKER := $(shell command -v podman || command -v docker)
NIX := $(shell command -v nix)

.packaging:
	mkdir -p ./packaging/

nix: .packaging ## Build Nix packages into ./packaging/
	echo "Building nix packages"
	for v in himmelblau himmelblau-desktop; do \
		$(NIX) --extra-experimental-features 'nix-command flakes' build ".#$$v" --out-link ./packaging/nix-$$v-result; \
	done

DEB_TARGETS := ubuntu22.04 ubuntu24.04 debian12 debian13
RPM_TARGETS := rocky8 rocky9 rocky10 tumbleweed rawhide fedora41 fedora42
SLE_TARGETS := sle15sp6 sle15sp7 sle16
ALL_PACKAGE_TARGETS := $(DEB_TARGETS) $(RPM_TARGETS) $(SLE_TARGETS)

install: ## Install packages from ./packaging onto this host (apt/dnf/yum/zypper auto-detected)
	@set -euo pipefail; \
	. /etc/os-release; \
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

uninstall: ## Uninstall Himmelblau packages from this host (apt/dnf/yum/zypper auto-detected)
	@set -e; \
	PM=""; PKGTYPE=""; \
	if command -v apt-get >/dev/null 2>&1; then \
		PKGTYPE="deb"; PM="sudo apt-get remove -y"; \
	elif command -v dnf >/dev/null 2>&1; then \
		PKGTYPE="rpm"; PM="sudo dnf remove -y"; \
	elif command -v yum >/dev/null 2>&1; then \
		PKGTYPE="rpm"; PM="sudo yum remove -y"; \
	elif command -v zypper >/dev/null 2>&1; then \
		PKGTYPE="rpm"; PM="sudo zypper rm -y"; \
	else \
		echo "Error: no supported package manager found (apt/dnf/yum/zypper)."; exit 2; \
	fi; \
	pkgs="himmelblau himmelblau-qr-greeter himmelblau-selinux himmelblau-sshd-config himmelblau-sso nss-himmelblau pam-himmelblau"; \
	echo "Removing: $$pkgs"; \
	$$PM $$pkgs; \
	echo "Uninstall complete."

dockerfiles:
	python3 scripts/gen_dockerfiles.py --out ./images/

deb-servicefiles:
	python3 ./scripts/gen_servicefiles.py --out ./platform/debian/

rpm-servicefiles:
	python3 ./scripts/gen_servicefiles.py --out ./platform/opensuse/

.PHONY: package deb rpm $(DEB_TARGETS) $(RPM_TARGETS) ${SLE_TARGETS} dockerfiles deb-servicefiles rpm-servicefiles install uninstall help sbom

check-licenses: ## Validate dependant licenses comply with GPLv3
	cargo deny -V >/dev/null || (echo "cargo-deny required" && cargo install cargo-deny)
	cargo deny --all-features check licenses

vet: ## Vet Dependencies
	cargo vet -V >/dev/null || (echo "cargo-vet required" && cargo install cargo-vet)
	cargo vet --locked || echo "Use |cargo vet inspect| to vet the changes to each crate"

sbom: .packaging ## Generate a Software Bill of Materials
	cargo sbom -V >/dev/null || (echo "cargo-sbom required" && cargo install cargo-sbom)
	cargo sbom > ./packaging/sbom.json

package: deb rpm sbom ## Build packages for all supported distros (DEB+RPM)
	ls ./packaging/

deb: $(DEB_TARGETS) ## Build all DEB targets

GPG_KEY_RSA_EL8   := 0xFFE471BA97CD96ED7330E0B4F5A25D2D6AA97EC9
GPG_KEY_ED25519   := 0x3D46C88168B2FF8D75D0B1786CCA48F23916FC03
rpm: $(RPM_TARGETS) $(SLE_TARGETS) sign-rpms ## Build all RPM targets; then sign RPMS with rpmsign

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

$(DEB_TARGETS): %: .packaging dockerfiles
	@echo "Building Ubuntu $@ packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build /bin/sh -c \
			'mv ./target/debian/*.deb ./packaging/'

$(RPM_TARGETS): %: .packaging dockerfiles
	@echo "Building $@ RPM packages"
	mkdir -p target/$@
	$(DOCKER) build -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build /bin/sh -c \
			'for f in ./target/generate-rpm/*.rpm; do \
				mv $$f $${f%.rpm}-$@.rpm; \
			done && mv ./target/generate-rpm/*.rpm ./packaging/'

$(SLE_TARGETS): %: .packaging dockerfiles
	@echo "Building $@ SLE RPM packages"
	mkdir -p target/$@
	$(DOCKER) build --secret id=scc_regcode,src=${HOME}/.secrets/scc_regcode -t himmelblau-$@-build -f images/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/himmelblau \
		-v $(CURDIR)/target/$@:/himmelblau/target \
		himmelblau-$@-build /bin/sh -c \
			'for f in ./target/generate-rpm/*.rpm; do \
				mv $$f $${f%.rpm}-$@.rpm; \
			done && mv ./target/generate-rpm/*.rpm ./packaging/'

# Pretty/help colors (safe if your shell prints raw escapes; adjust or remove if you prefer plain)
HELP_COL := \033[36m
HELP_RST := \033[0m

help: ## Show this help
	@printf "Himmelblau Packaging Makefile\n\n"
	@printf "Usage:\n  make [target]\n\n"
	@printf "Common targets:\n"
	@awk 'BEGIN {FS = ":.*##"} \
	     /^[A-Za-z0-9_.-]+:.*##/ { \
	         printf "  %s%-18s%s %s\n", "$(HELP_COL)", $$1, "$(HELP_RST)", $$2 \
	     }' $(MAKEFILE_LIST)
	@printf "\nPer-distro build targets (build only that distro):\n"
	@for t in $(ALL_PACKAGE_TARGETS); do printf "  - %s\n" "make $$t"; done
	@printf "\nDetected tools:\n  DOCKER: %s\n  NIX: %s\n" "$(DOCKER)" "$(NIX)"
	@printf "\nTips:\n"
	@printf "  • Running plain 'make' invokes the default 'all' target (auto-detects host distro).\n"
	@printf "  • You can install a development build of Himmelblau on the current host with 'make && sudo make install'\n"
	@printf "  • Built packages are written to ./packaging/\n\n"
	@printf "If you'd like a new distro added to the supported packages list, contact a maintainer. We're happy to help.\n"
