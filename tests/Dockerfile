FROM opensuse/tumbleweed
MAINTAINER David Mulder <dmulder@suse.com>

COPY himmelblau.tar.gz /home
RUN mkdir /etc/himmelblau && touch /etc/himmelblau/himmelblau.conf
RUN mkdir -p /var/run/himmelblaud; mkdir -p /var/lib/himmelblau/private

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
	python3-msal && \
	zypper clean;

# Build himmelblau
RUN pushd /home; tar -xf himmelblau.tar.gz && cargo build; popd
RUN pushd /home; install -m 0755 target/debug/libnss_himmelblau.so /usr/lib64/libnss_himmelblau.so.2; popd
RUN ln -s /usr/lib64/libnss_himmelblau.so.2 /usr/lib64/libnss_himmelblau.so
RUN pushd /home; install -m 0755 target/debug/libpam_himmelblau.so /usr/lib64/security/pam_himmelblau.so; popd
RUN pushd /home; install -m 0755 target/debug/himmelblaud /usr/sbin; popd
RUN pushd /home; install -m 0755 target/debug/aad-tool /usr/bin; popd

# Configure pam
RUN printf "auth\trequired\tpam_env.so\nauth\tsufficient\tpam_himmelblau.so\nauth\trequired\tpam_unix.so\ttry_first_pass\n" > /etc/pam.d/common-auth

# Configure nss
RUN printf "passwd: compat himmelblau\ngroup: compat himmelblau\nshadow: compat himmelblau" > /etc/nsswitch.conf

ENTRYPOINT ["/usr/bin/catatonit", "--", "/root/tests/test.sh"]
