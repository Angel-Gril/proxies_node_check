#!/bin/sh
# Create only the new application's namespace; leave existing sites untouched.
set -eu
NODECHECK_DEPLOY_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$NODECHECK_DEPLOY_DIR/common.sh"
test "$(id -u)" -eq 0
test ! -e /opt/nodecheck
test ! -e /etc/nodecheck
test ! -e /etc/nginx/sites-available/nodecheck
test ! -e /etc/nginx/sites-enabled/nodecheck
test ! -e /etc/systemd/system/nodecheck.service
if getent passwd nodecheck >/dev/null; then echo 'nodecheck user already exists; stop.'; exit 1; fi
if ss -H -lnt 'sport = :18765' | grep -q .; then echo 'Port 18765 is occupied; stop.'; exit 1; fi
nginx -t
install -d -m 0755 /opt/nodecheck/app /opt/nodecheck/bin /var/lib/nodecheck-acme/.well-known/acme-challenge
install -d -m 0700 /etc/nodecheck
cat > /etc/nginx/sites-available/nodecheck <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $NODECHECK_DOMAIN;
    access_log off;
    error_log /dev/null crit;
    location /.well-known/acme-challenge/ { root /var/lib/nodecheck-acme; }
    location / { return 503; }
}
NGINX
ln -s /etc/nginx/sites-available/nodecheck /etc/nginx/sites-enabled/nodecheck
if nginx -t; then
    systemctl reload nginx
else
    unlink /etc/nginx/sites-enabled/nodecheck
    exit 1
fi
printf 'nodecheck-origin-validation' > /var/lib/nodecheck-acme/.well-known/acme-challenge/nodecheck-origin-check
echo 'Independent HTTP challenge site prepared; existing apps continue running.'
