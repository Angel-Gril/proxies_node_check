# Shared by the deployment scripts. Sourcing this file has no external effects.
if [ -z "${NODECHECK_DOMAIN:-}" ]; then
    echo 'Set NODECHECK_DOMAIN to your own domain, for example check.example.com.' >&2
    return 1
fi
case "$NODECHECK_DOMAIN" in
    *[!a-zA-Z0-9.-]*)
        echo 'NODECHECK_DOMAIN must contain only DNS hostname characters.' >&2
        return 1
        ;;
esac
if [ "${#NODECHECK_DOMAIN}" -gt 253 ] || ! printf '%s\n' "$NODECHECK_DOMAIN" | LC_ALL=C grep -Eq '^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'; then
    echo 'NODECHECK_DOMAIN must be a DNS hostname, without a scheme, port, path, or whitespace.' >&2
    return 1
fi
NODECHECK_DOMAIN=$(printf '%s' "$NODECHECK_DOMAIN" | tr '[:upper:]' '[:lower:]')

render_nginx_config() {
    # Replace only our placeholder; leave Nginx variables such as $host intact.
    sed "s/__NODECHECK_DOMAIN__/$NODECHECK_DOMAIN/g" "$NODECHECK_DEPLOY_DIR/nginx.conf"
}

render_renewal_hook() {
    cat <<HOOK
#!/bin/sh
set -eu
if [ "\${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/$NODECHECK_DOMAIN" ]; then
    /usr/sbin/nginx -t && /bin/systemctl reload nginx
fi
HOOK
}
