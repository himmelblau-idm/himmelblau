FROM opensuse/tumbleweed
MAINTAINER David Mulder <dmulder@suse.com>

RUN mkdir /etc/himmelblau && touch /etc/himmelblau/himmelblau.conf
RUN mkdir -p /var/run/himmelblaud; mkdir -p /var/cache/himmelblau

# Install dependencies
RUN zypper ar --no-gpgcheck https://mirrorcache-us.opensuse.org/repositories/network:/samba:/TESTING/openSUSE_Tumbleweed/network%3Asamba%3ATESTING.repo
RUN zypper --non-interactive install \
	systemd \
	pam \
	glibc \
	tar \
	catatonit \
	gcc \
	cargo-packaging \
	libopenssl-devel \
	pam-devel \
	python3-devel \
	python3-python-pam \
	libpamtest-devel \
	sqlite3-devel \
	python3-msal && \
	zypper clean;

# Configure pam
RUN printf "auth\trequired\tpam_env.so\nauth\tsufficient\tpam_himmelblau.so\nauth\trequired\tpam_unix.so\ttry_first_pass\n" > /etc/pam.d/common-auth

# Configure nss
RUN printf "passwd: compat himmelblau\ngroup: compat himmelblau\nshadow: compat himmelblau" > /etc/nsswitch.conf

ENTRYPOINT ["/usr/bin/catatonit", "--", "/root/tests/test.sh"]
