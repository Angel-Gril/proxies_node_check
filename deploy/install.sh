#!/bin/sh
set -eu
test "$(id -u)" -eq 0
test -f /etc/nodecheck/app.env
test ! -e /etc/systemd/system/nodecheck.service
if ss -H -lnt 'sport = :18765' | grep -q .; then echo 'Port 18765 is occupied; stop.'; exit 1; fi
if ! getent passwd nodecheck >/dev/null; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nodecheck
fi
python3 -m venv /opt/nodecheck/venv
/opt/nodecheck/venv/bin/pip install --disable-pip-version-check -r /opt/nodecheck/app/requirements.txt
/opt/nodecheck/venv/bin/python /opt/nodecheck/app/tools/install_mihomo.py --output /opt/nodecheck/bin/mihomo
chmod 0600 /etc/nodecheck/app.env
/opt/nodecheck/venv/bin/python -m unittest discover -s /opt/nodecheck/app/tests -v
certbot certonly --webroot -w /var/lib/nodecheck-acme -d proxies.20260610.xyz --cert-name proxies.20260610.xyz --non-interactive --agree-tos --register-unsafely-without-email
install -m 0644 /opt/nodecheck/app/deploy/nodecheck.service /etc/systemd/system/nodecheck.service
install -m 0644 /opt/nodecheck/app/deploy/nginx.conf /etc/nginx/sites-available/nodecheck
nginx -t
systemctl daemon-reload
systemctl enable --now nodecheck.service
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:18765/healthz
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/nodecheck-reload <<'HOOK'
#!/bin/sh
if [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/proxies.20260610.xyz ]; then
    /usr/sbin/nginx -t && /bin/systemctl reload nginx
fi
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/nodecheck-reload
echo 'Nodecheck installed independently on 127.0.0.1:18765.'
