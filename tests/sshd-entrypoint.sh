#!/bin/sh
set -eu
umask 077
printf '%s\n' "${TEST_SSH_PUBLIC_KEY:?}" > /home/fixture/.ssh/authorized_keys
chown -R fixture:fixture /home/fixture/.ssh
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PermitRootLogin=no -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -o AllowUsers=fixture -o LogLevel=VERBOSE
