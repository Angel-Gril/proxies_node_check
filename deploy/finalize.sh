#!/bin/sh
set -eu
test "$(id -u)" -eq 0
test -x /opt/nodecheck/venv/bin/gunicorn
test -x /opt/nodecheck/bin/mihomo
test -f /etc/nodecheck/app.env
test -f /etc/nginx/sites-available/nodecheck
test -f /etc/letsencrypt/live/proxies.20260610.xyz/fullchain.pem
test -f /etc/letsencrypt/live/proxies.20260610.xyz/privkey.pem

# The service reads the EnvironmentFile before dropping privileges; group access
# keeps the secret out of all other users while allowing the service to start.
chown root:nodecheck /etc/nodecheck/app.env
chmod 0640 /etc/nodecheck/app.env
chown -R root:nodecheck /opt/nodecheck/app
find /opt/nodecheck/app -type d -exec chmod 0750 {} +
find /opt/nodecheck/app -type f -exec chmod 0640 {} +
chmod 0750 /opt/nodecheck/bin /opt/nodecheck/bin/mihomo
chown root:nodecheck /opt/nodecheck/bin/mihomo
chmod 0750 /opt/nodecheck/bin/mihomo

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nodecheck-reload <<'HOOK'
#!/bin/sh
set -eu
if [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/proxies.20260610.xyz ]; then
    /usr/sbin/nginx -t && /bin/systemctl reload nginx
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/nodecheck-reload

systemctl daemon-reload
systemctl restart nodecheck
curl --fail --silent --show-error --max-time 15 http://127.0.0.1:18765/healthz
nginx -t
systemctl reload nginx
sleep 1
curl --fail --silent --show-error --max-time 15 --resolve proxies.20260610.xyz:443:127.0.0.1 https://proxies.20260610.xyz/login -o /dev/null
echo 'Nodecheck service and dedicated HTTPS site are ready.'
