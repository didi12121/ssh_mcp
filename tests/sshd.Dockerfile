FROM alpine:3
RUN apk add --no-cache openssh-server tmux python3 \
    && adduser -D -s /bin/sh fixture \
    && passwd -d fixture \
    && mkdir -p /run/sshd /home/fixture/.ssh \
    && chmod 700 /home/fixture/.ssh
COPY sshd-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
