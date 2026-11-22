# Fatima Desk server image: same layout as rustdesk/rustdesk-server
# (docker-classic/Dockerfile), built from our own hbbs/hbbr, which add
# custom-ID support. The binaries come from the "Fatima Desk server build"
# GitHub workflow (static x86_64 musl).
FROM scratch
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
