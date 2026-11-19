# A plain Debian with a multi-user nix install and a user without any
# dotfiles, to try the sandbox the way a new user meets it. See `make demo`.
FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl xz-utils git util-linux \
	&& rm -rf /var/lib/apt/lists/*

# The official multi-user installer; without systemd it leaves starting
# nix-daemon to us (entrypoint.sh).
RUN curl -fsSL https://nixos.org/nix/install | sh -s -- --daemon --yes

# Flakes, as the README's install command needs them. The image has no
# CAP_SYS_ADMIN for nix's build sandbox; builds still go through the daemon.
RUN printf '%s\n' 'experimental-features = nix-command flakes' 'sandbox = false' >> /etc/nix/nix.conf \
	&& git config --system --add safe.directory '*'

RUN useradd --create-home --shell /bin/bash tester \
	&& mkdir /home/tester/project \
	&& chown tester:tester /home/tester/project

COPY entrypoint.sh /entrypoint.sh
WORKDIR /home/tester/project
ENTRYPOINT ["/entrypoint.sh"]
