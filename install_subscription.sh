#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# VPS Subscription API Installer V2
# ============================================================

APP_NAME="subscription-api"
API_SCRIPT="/root/subscription_api.py"
API_PORT="8765"
NODE_FILE="/root/singbox_nodes.txt"

NGINX_SSL_ROOT="/etc/nginx/ssl"
NGINX_CONF_DIR="/etc/nginx/conf.d"

CERT_LIST="/tmp/subscription_cert_list.txt"

DOMAIN=""
CERT_SRC=""
KEY_SRC=""
CERT_DST=""
KEY_DST=""

# ============================================================
# 输出
# ============================================================

info() {
    echo -e "\033[1;36m[INFO]\033[0m $*"
}

success() {
    echo -e "\033[1;32m[ OK ]\033[0m $*"
}

warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

die() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
    exit 1
}

trap 'die "脚本执行失败，行号：$LINENO"' ERR

# ============================================================
# Root
# ============================================================

check_root() {
    [[ "$EUID" -eq 0 ]] || die "请使用 root 用户运行。"
}

# ============================================================
# 系统检测
# ============================================================

detect_system() {

    [[ -f /etc/os-release ]] || die "无法识别系统。"

    . /etc/os-release

    OS_NAME="${PRETTY_NAME:-$ID}"

    info "操作系统：${OS_NAME}"

    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    else
        die "不支持的系统：未找到 apt/apk/dnf/yum。"
    fi

    info "包管理器：${PKG_MANAGER}"
}

# ============================================================
# 安装依赖
# ============================================================

install_dependencies() {

    info "检查并安装依赖..."

    case "$PKG_MANAGER" in

        apt)
            export DEBIAN_FRONTEND=noninteractive

            apt-get update

            apt-get install -y \
                python3 \
                nginx \
                openssl \
                ca-certificates \
                curl
            ;;

        apk)
            apk add --no-cache \
                python3 \
                nginx \
                openssl \
                ca-certificates \
                curl
            ;;

        dnf)
            dnf install -y \
                python3 \
                nginx \
                openssl \
                ca-certificates \
                curl
            ;;

        yum)
            yum install -y \
                python3 \
                nginx \
                openssl \
                ca-certificates \
                curl
            ;;

    esac

    command -v python3 >/dev/null 2>&1 ||
        die "Python3 安装失败。"

    command -v openssl >/dev/null 2>&1 ||
        die "OpenSSL 安装失败。"

    command -v nginx >/dev/null 2>&1 ||
        die "Nginx 安装失败。"

    command -v curl >/dev/null 2>&1 ||
        die "curl 安装失败。"

    success "系统依赖正常。"
}

# ============================================================
# 证书扫描
# ============================================================

search_certificates() {

    info "正在搜索 SSL 证书..."

    : > "$CERT_LIST"

    local cert
    local key
    local cn
    local san
    local issuer
    local not_before
    local not_after

    while IFS= read -r cert; do

        [[ -f "$cert" ]] || continue

        if ! openssl x509 \
            -in "$cert" \
            -noout >/dev/null 2>&1
        then
            continue
        fi

        cn="$(
            openssl x509 \
                -in "$cert" \
                -noout \
                -subject 2>/dev/null |
            sed -n 's/.*CN[[:space:]]*=[[:space:]]*//p' |
            sed 's/,.*//' |
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//' ||
            true
        )"

        [[ -n "$cn" ]] || continue

        san="$(
            openssl x509 \
                -in "$cert" \
                -noout \
                -ext subjectAltName 2>/dev/null |
            grep -oE 'DNS:[^, ]+' |
            sed 's/^DNS://' |
            paste -sd ',' - ||
            true
        )"

        issuer="$(
            openssl x509 \
                -in "$cert" \
                -noout \
                -issuer 2>/dev/null |
            sed 's/^issuer=//' ||
            true
        )"

        not_before="$(
            openssl x509 \
                -in "$cert" \
                -noout \
                -startdate 2>/dev/null |
            cut -d= -f2 ||
            true
        )"

        not_after="$(
            openssl x509 \
                -in "$cert" \
                -noout \
                -enddate 2>/dev/null |
            cut -d= -f2 ||
            true
        )"

        key=""

        for candidate in \
            "$(dirname "$cert")/privkey.pem" \
            "$(dirname "$cert")/key.pem" \
            "$(dirname "$cert")/private.key" \
            "$(dirname "$cert")/privkey.key"
        do

            if [[ -f "$candidate" ]]; then

                if openssl pkey \
                    -in "$candidate" \
                    -noout >/dev/null 2>&1
                then
                    key="$candidate"
                    break
                fi

            fi

        done

        [[ -n "$key" ]] || continue

        # ====================================================
        # 验证证书和私钥是否匹配
        # ====================================================

        cert_pub="$(
            openssl x509 \
                -in "$cert" \
                -pubkey \
                -noout 2>/dev/null |
            openssl pkey \
                -pubin \
                -outform DER 2>/dev/null |
            sha256sum |
            awk '{print $1}' ||
            true
        )"

        key_pub="$(
            openssl pkey \
                -in "$key" \
                -pubout 2>/dev/null |
            openssl pkey \
                -pubin \
                -outform DER 2>/dev/null |
            sha256sum |
            awk '{print $1}' ||
            true
        )"

        [[ -n "$cert_pub" ]] || continue
        [[ -n "$key_pub" ]] || continue
        [[ "$cert_pub" == "$key_pub" ]] || continue

        printf '%s	%s	%s	%s	%s	%s	%s
' \
            "$cn" \
            "$san" \
            "$cert" \
            "$key" \
            "$issuer" \
            "$not_before" \
            "$not_after" \
            >> "$CERT_LIST"

    done < <(
        find \
            /root \
            /etc \
            /usr/local \
            /opt \
            -type f \
            \( \
                -name "fullchain.pem" \
                -o -name "cert.pem" \
                -o -name "*.crt" \
            \) \
            2>/dev/null |
        sort -u
    )

    if [[ -s "$CERT_LIST" ]]; then
        sort -u "$CERT_LIST" -o "$CERT_LIST"
    fi

    local count
    count="$(wc -l < "$CERT_LIST" | tr -d ' ')"

    if [[ "$count" -eq 0 ]]; then
        die "没有找到证书和匹配私钥。"
    fi

    success "发现 ${count} 个可用证书。"
}

# ============================================================
# 选择证书
# ============================================================

select_certificate() {

    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[1;36m%s\033[0m\n' "                    可用 SSL 证书"
    printf '\033[0;90m%s\033[0m\n' "============================================================"

    local index=0

    while IFS=$'\t' read -r \
        cn san cert key issuer not_before not_after
    do

        index=$((index + 1))

        echo
        printf '\033[1;36m%s\033[0m\n' "[${index}] ${cn}"
        printf '\033[0;90m%s\033[0m\n' "    SAN      : ${san}"
        printf '\033[0;90m%s\033[0m\n' "    Issuer   : ${issuer}"
        printf '\033[0;90m%s\033[0m\n' "    有效期   : ${not_before} -> ${not_after}"
        printf '\033[0;90m%s\033[0m\n' "    Cert     : ${cert}"
        printf '\033[0;90m%s\033[0m\n' "    Key      : ${key}"

    done < "$CERT_LIST"

    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[1;33m%s\033[0m\n' "请输入编号，或者直接输入域名。"
    printf '\033[1;33m%s\033[0m\n' "例如：1"
    printf '\033[1;33m%s\033[0m\n' "或者：sys.nl8.eu"
    printf '\033[0;90m%s\033[0m\n' "============================================================"

    local choice
    local selected

    read -r -p $'\033[1;33m请选择证书: \033[0m' choice

    [[ -n "$choice" ]] ||
        die "没有输入选择。"

    if [[ "$choice" =~ ^[0-9]+$ ]]; then

        selected="$(sed -n "${choice}p" "$CERT_LIST")"

        [[ -n "$selected" ]] ||
            die "不存在证书编号：$choice"

    else

        selected="$(
            awk -F '\t' -v domain="$choice" '
                $1 == domain {
                    print
                    exit
                }

                $2 != "" {
                    n = split($2, a, ",")

                    for (i = 1; i <= n; i++) {
                        if (a[i] == domain) {
                            print
                            exit
                        }
                    }
                }
            ' "$CERT_LIST"
        )"

        [[ -n "$selected" ]] ||
            die "没有找到域名：$choice"
    fi

    IFS=$'\t' read -r \
        DOMAIN \
        SAN \
        CERT_SRC \
        KEY_SRC \
        ISSUER \
        NOT_BEFORE \
        NOT_AFTER \
        <<< "$selected"

    CERT_DST="${NGINX_SSL_ROOT}/${DOMAIN}/fullchain.pem"
    KEY_DST="${NGINX_SSL_ROOT}/${DOMAIN}/privkey.pem"

    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[1;36m%s\033[0m\n' "                    已选择证书"
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[0;37m%s\033[0m\n' "域名       : ${DOMAIN}"
    printf '\033[0;90m%s\033[0m\n' "证书来源   : ${CERT_SRC}"
    printf '\033[0;90m%s\033[0m\n' "私钥来源   : ${KEY_SRC}"
    printf '\033[0;90m%s\033[0m\n' "Nginx证书  : ${CERT_DST}"
    printf '\033[0;90m%s\033[0m\n' "Nginx私钥  : ${KEY_DST}"
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    echo
}

# ============================================================
# 复制证书
# ============================================================

install_certificate() {

    info "复制证书给 Nginx 使用..."

    mkdir -p "${NGINX_SSL_ROOT}/${DOMAIN}"

    cp -f "$CERT_SRC" "$CERT_DST"
    cp -f "$KEY_SRC" "$KEY_DST"

    chmod 644 "$CERT_DST"
    chmod 600 "$KEY_DST"

    openssl x509 \
        -in "$CERT_DST" \
        -noout >/dev/null

    openssl pkey \
        -in "$KEY_DST" \
        -noout >/dev/null

    success "证书复制完成。"
}

# ============================================================
# 节点文件
# ============================================================

prepare_node_file() {

    if [[ ! -f "$NODE_FILE" ]]; then

        warn "未找到 ${NODE_FILE}"

        cat > "$NODE_FILE" <<'NODE_EOF'
# VPS 节点订阅
# 每行一个节点链接
#
# 示例：
# vless://...
# hysteria2://...
NODE_EOF

        chmod 600 "$NODE_FILE"

        warn "已经创建空的节点文件。"

    else

        chmod 600 "$NODE_FILE"

        success "节点文件存在：${NODE_FILE}"
    fi
}

# ============================================================
# Python API
# ============================================================

install_api() {

    info "安装 Python Subscription API..."

    cat > "$API_SCRIPT" <<'PY_EOF'
#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import base64

NODE_FILE = Path("/root/singbox_nodes.txt")
HOST = "127.0.0.1"
PORT = 8765


class SubscriptionHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path != "/subs":
            self.send_response(404)
            self.end_headers()
            return

        try:

            if not NODE_FILE.exists():
                raise FileNotFoundError(
                    str(NODE_FILE)
                )

            lines = NODE_FILE.read_text(
                encoding="utf-8"
            ).splitlines()

            nodes = []

            for line in lines:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                nodes.append(line)

            content = "\n".join(nodes)

            if content:
                content += "\n"

            body = base64.b64encode(
                content.encode("utf-8")
            )

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(len(body))
            )

            self.send_header(
                "Cache-Control",
                "no-cache, no-store, must-revalidate"
            )

            self.send_header(
                "Pragma",
                "no-cache"
            )

            self.end_headers()

            self.wfile.write(body)

        except Exception as exc:

            body = (
                f"Subscription error: {exc}\n"
            ).encode("utf-8")

            self.send_response(500)

            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8"
            )

            self.send_header(
                "Content-Length",
                str(len(body))
            )

            self.end_headers()

            self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":

    server = ThreadingHTTPServer(
        (HOST, PORT),
        SubscriptionHandler
    )

    print(
        "Subscription API listening on "
        "http://127.0.0.1:8765/subs",
        flush=True
    )

    server.serve_forever()
PY_EOF

    chmod 700 "$API_SCRIPT"

    success "Python API 创建完成。"
}

# ============================================================
# systemd
# ============================================================

install_systemd() {

    if ! command -v systemctl >/dev/null 2>&1; then
        die "当前系统没有 systemd。"
    fi

    info "创建 systemd 服务..."

    cat > "/etc/systemd/system/${APP_NAME}.service" <<SERVICE_EOF
[Unit]
Description=VPS Node Subscription API
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /root/subscription_api.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    systemctl daemon-reload

    systemctl enable "$APP_NAME.service" >/dev/null

    systemctl restart "$APP_NAME.service"

    sleep 1

    systemctl is-active \
        --quiet "$APP_NAME.service" ||
        die "Subscription API 启动失败。"

    success "Subscription API 服务运行正常。"
}

# ============================================================
# API 测试
# ============================================================

test_api() {

    info "测试本地 API..."

    local result

    result="$(
        curl \
            -fsS \
            --max-time 5 \
            "http://127.0.0.1:${API_PORT}/subs"
    )" || die "本地 API 测试失败。"

    if [[ -n "$result" ]]; then
        success "API 返回 Base64 订阅内容。"
    else
        warn "API 正常，但当前节点文件为空。"
    fi
}

# ============================================================
# Nginx
# ============================================================

configure_nginx() {

    info "配置 Nginx..."

    mkdir -p "$NGINX_CONF_DIR"

    local nginx_conf="${NGINX_CONF_DIR}/${DOMAIN}.conf"

    cat > "$nginx_conf" <<NGINX_EOF
server {
    listen 80;
    listen [::]:80;

    server_name ${DOMAIN};

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name ${DOMAIN};

    ssl_certificate     ${CERT_DST};
    ssl_certificate_key ${KEY_DST};

    ssl_protocols TLSv1.2 TLSv1.3;

    location = /subs {

        proxy_pass http://127.0.0.1:${API_PORT}/subs;

        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_no_cache 1;
        proxy_cache_bypass 1;

        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
    }
}
NGINX_EOF

    if [[ -d /etc/nginx/sites-enabled ]]; then
        rm -f /etc/nginx/sites-enabled/default
    fi

    nginx -t

    systemctl enable nginx >/dev/null 2>&1 || true

    systemctl restart nginx

    success "Nginx 配置完成。"
}

# ============================================================
# HTTPS 测试
# ============================================================

test_https() {

    info "测试 HTTPS /subs..."

    local url="https://${DOMAIN}/subs"

    if curl \
        -kfsS \
        --max-time 10 \
        "$url" \
        >/tmp/subscription_https_test.txt
    then

        if [[ -s /tmp/subscription_https_test.txt ]]; then
            success "HTTPS /subs 工作正常。"
        else
            warn "HTTPS /subs 正常，但节点文件为空。"
        fi

    else

        die "HTTPS /subs 测试失败：${url}"
    fi
}

# ============================================================
# 证书同步脚本
# ============================================================

install_certificate_sync() {

    info "安装证书自动同步..."

    cat > /usr/local/sbin/sync-subscription-cert.sh <<SYNC_EOF
#!/usr/bin/env bash

set -e

SRC_CERT="${CERT_SRC}"
SRC_KEY="${KEY_SRC}"

DST_CERT="${CERT_DST}"
DST_KEY="${KEY_DST}"

changed=0

if [[ -f "\${SRC_CERT}" ]]; then

    if ! cmp -s "\${SRC_CERT}" "\${DST_CERT}" 2>/dev/null; then

        cp -f "\${SRC_CERT}" "\${DST_CERT}"

        chmod 644 "\${DST_CERT}"

        changed=1
    fi

fi

if [[ -f "\${SRC_KEY}" ]]; then

    if ! cmp -s "\${SRC_KEY}" "\${DST_KEY}" 2>/dev/null; then

        cp -f "\${SRC_KEY}" "\${DST_KEY}"

        chmod 600 "\${DST_KEY}"

        changed=1
    fi

fi

if [[ "\${changed}" -eq 1 ]]; then

    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx
    fi

fi
SYNC_EOF

    chmod 700 /usr/local/sbin/sync-subscription-cert.sh

    cat > /etc/systemd/system/subscription-cert-sync.service <<SERVICE_EOF
[Unit]
Description=Sync subscription SSL certificate

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sync-subscription-cert.sh
SERVICE_EOF

    cat > /etc/systemd/system/subscription-cert-sync.timer <<TIMER_EOF
[Unit]
Description=Check subscription SSL certificate

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
TIMER_EOF

    systemctl daemon-reload

    systemctl enable \
        --now \
        subscription-cert-sync.timer

    success "证书自动同步已启用，每 6 小时检查一次。"
}

# ============================================================
# 完成
# ============================================================

show_result() {

    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[1;32m%s\033[0m\n' "                    部署完成"
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    echo
    printf '\033[0;90m%s\033[0m\n' "系统："
    printf '\033[0;37m%s\033[0m\n' "  ${OS_NAME}"
    echo
    printf '\033[0;90m%s\033[0m\n' "域名："
    printf '\033[0;37m%s\033[0m\n' "  ${DOMAIN}"
    echo
    printf '\033[0;90m%s\033[0m\n' "证书来源："
    printf '\033[0;37m%s\033[0m\n' "  ${CERT_SRC}"
    echo
    printf '\033[0;90m%s\033[0m\n' "Nginx 证书："
    printf '\033[0;37m%s\033[0m\n' "  ${CERT_DST}"
    echo
    printf '\033[0;90m%s\033[0m\n' "节点文件："
    printf '\033[0;37m%s\033[0m\n' "  ${NODE_FILE}"
    echo
    printf '\033[0;90m%s\033[0m\n' "本地 API："
    printf '\033[1;34m%s\033[0m\n' "  http://127.0.0.1:${API_PORT}/subs"
    echo
    printf '\033[1;36m%s\033[0m\n' "v2rayN 订阅地址："
    printf '\033[1;34m%s\033[0m\n' "  https://${DOMAIN}/subs"
    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    echo
    printf '\033[0;90m%s\033[0m\n' "以后修改："
    printf '\033[0;37m%s\033[0m\n' "  ${NODE_FILE}"
    echo
    printf '\033[1;33m%s\033[0m\n' "修改节点后，v2rayN 直接刷新订阅即可。"
    echo
}

# ============================================================
# 主程序
# ============================================================

main() {

    echo
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    printf '\033[1;36m%s\033[0m\n' "       VPS Node Subscription API Installer V2"
    printf '\033[0;90m%s\033[0m\n' "============================================================"
    echo

    check_root

    detect_system

    install_dependencies

    search_certificates

    select_certificate

    install_certificate

    prepare_node_file

    install_api

    install_systemd

    test_api

    configure_nginx

    test_https

    install_certificate_sync

    show_result
}

main "$@"
