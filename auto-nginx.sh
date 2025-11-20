#!/bin/bash

# 哪吒面板 Nginx 反向代理一键配置脚本
# 功能：域名解析检测 + acme.sh SSL证书申请 + 反向代理配置

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 显示标题
show_banner() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  哪吒面板 Nginx 反向代理一键配置${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
}

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "无法检测操作系统"
        exit 1
    fi
    log_info "检测到操作系统: $OS $OS_VERSION"
}

# 安装依赖
install_dependencies() {
    log_step "检查并安装必要依赖..."
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y curl socat cron wget dnsutils net-tools -qq > /dev/null 2>&1
    elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]] || [[ "$OS" == "almalinux" ]]; then
        yum install -y curl socat cronie wget bind-utils net-tools -q > /dev/null 2>&1
    else
        log_error "不支持的操作系统: $OS"
        exit 1
    fi
    
    # 安装 Nginx
    if ! command -v nginx &> /dev/null; then
        log_warn "未检测到 Nginx，正在安装..."
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            apt-get install -y nginx -qq > /dev/null 2>&1
        else
            yum install -y nginx -q > /dev/null 2>&1
        fi
        systemctl enable nginx > /dev/null 2>&1
        systemctl start nginx > /dev/null 2>&1
    fi
    
    log_info "依赖安装完成"
}

# 获取服务器公网 IP
get_server_ip() {
    log_step "获取服务器公网 IP..."
    SERVER_IP=$(timeout 10 curl -s4 ifconfig.me 2>/dev/null || timeout 10 curl -s4 icanhazip.com 2>/dev/null || timeout 10 curl -s4 api.ipify.org 2>/dev/null)
    
    if [[ -z "$SERVER_IP" ]]; then
        log_error "无法获取服务器公网 IP"
        exit 1
    fi
    
    log_info "服务器 IP: ${GREEN}${SERVER_IP}${NC}"
}

# 检测域名解析
check_dns_resolution() {
    local domain=$1
    log_step "检测域名解析..."
    
    DOMAIN_IP=$(timeout 10 dig +short A "$domain" @8.8.8.8 2>/dev/null | grep -E '^[0-9.]+$' | head -n1)
    
    if [[ -z "$DOMAIN_IP" ]]; then
        log_error "域名未解析或解析失败"
        echo -e "  ${YELLOW}请将域名 A 记录解析到: ${GREEN}${SERVER_IP}${NC}"
        return 1
    fi
    
    log_info "域名解析 IP: ${BLUE}${DOMAIN_IP}${NC}"
    
    if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        log_info "✓ 域名解析正确"
        return 0
    else
        log_error "域名解析不匹配"
        echo -e "  ${RED}当前解析: ${DOMAIN_IP}${NC}"
        echo -e "  ${GREEN}应该解析: ${SERVER_IP}${NC}"
        return 1
    fi
}

# 安装 acme.sh
install_acme() {
    if [[ -f ~/.acme.sh/acme.sh ]]; then
        log_info "acme.sh 已安装"
        return 0
    fi
    
    log_step "安装 acme.sh..."
    curl -s https://get.acme.sh | sh > /dev/null 2>&1
    
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log_error "acme.sh 安装失败"
        return 1
    fi
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
    log_info "acme.sh 安装完成"
}

# 申请 SSL 证书
issue_ssl_cert() {
    local domain=$1
    local cert_dir="/etc/nginx/ssl/${domain}"
    
    log_step "申请 SSL 证书..."
    
    mkdir -p "$cert_dir"
    
    # 停止 Nginx
    systemctl stop nginx > /dev/null 2>&1
    sleep 2
    
    # 检查端口占用
    if netstat -tuln 2>/dev/null | grep -q ':80 ' || ss -tuln 2>/dev/null | grep -q ':80 '; then
        log_error "80 端口被占用"
        systemctl start nginx > /dev/null 2>&1
        return 1
    fi
    
    # 申请证书
    if ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --keylength ec-256 > /dev/null 2>&1; then
        log_info "✓ 证书申请成功"
    else
        log_error "证书申请失败"
        systemctl start nginx > /dev/null 2>&1
        return 1
    fi
    
    # 安装证书
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc \
        --fullchain-file "${cert_dir}/fullchain.pem" \
        --key-file "${cert_dir}/key.pem" \
        --reloadcmd "systemctl reload nginx" > /dev/null 2>&1
    
    chmod 644 "${cert_dir}/fullchain.pem"
    chmod 600 "${cert_dir}/key.pem"
    
    systemctl start nginx > /dev/null 2>&1
    
    SSL_CERT="${cert_dir}/fullchain.pem"
    SSL_KEY="${cert_dir}/key.pem"
    
    log_info "证书安装到: $cert_dir"
    return 0
}

# 检测 Nginx 版本
detect_nginx_version() {
    NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
    log_info "Nginx 版本: $NGINX_VERSION"
    
    local major minor patch
    major=$(echo "$NGINX_VERSION" | cut -d. -f1)
    minor=$(echo "$NGINX_VERSION" | cut -d. -f2)
    patch=$(echo "$NGINX_VERSION" | cut -d. -f3)
    
    USE_NEW_HTTP2=false
    if [[ $major -gt 1 ]] || [[ $major -eq 1 && $minor -gt 25 ]] || [[ $major -eq 1 && $minor -eq 25 && $patch -gt 1 ]]; then
        USE_NEW_HTTP2=true
    fi
}

# 生成 Nginx 配置
generate_nginx_config() {
    local domain=$1
    local port=$2
    local use_cdn=$3
    local cdn_header=$4
    local cdn_range=$5
    local outermost=$6
    
    if [[ -d "/etc/nginx/sites-available" ]]; then
        CONFIG_FILE="/etc/nginx/sites-available/nezha-${domain}.conf"
        ENABLED_FILE="/etc/nginx/sites-enabled/nezha-${domain}.conf"
    else
        CONFIG_FILE="/etc/nginx/conf.d/nezha-${domain}.conf"
        ENABLED_FILE=""
    fi
    
    log_step "生成配置文件..."
    
    cat > "$CONFIG_FILE" << EOF
upstream dashboard {
    server 127.0.0.1:${port};
    keepalive 512;
}

server {
EOF

    if [[ $USE_NEW_HTTP2 == true ]]; then
        echo "    listen 443 ssl;" >> "$CONFIG_FILE"
        echo "    listen [::]:443 ssl;" >> "$CONFIG_FILE"
        echo "    http2 on;" >> "$CONFIG_FILE"
    else
        echo "    listen 443 ssl http2;" >> "$CONFIG_FILE"
        echo "    listen [::]:443 ssl http2;" >> "$CONFIG_FILE"
    fi

    cat >> "$CONFIG_FILE" << EOF

    server_name ${domain};
    
    ssl_certificate ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};
    ssl_stapling on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    underscores_in_headers on;
EOF

    if [[ $use_cdn == "y" ]]; then
        cat >> "$CONFIG_FILE" << EOF
    
    set_real_ip_from ${cdn_range};
    real_ip_header ${cdn_header};
EOF
    fi

    local nz_realip_grpc nz_realip_ws nz_realip_web
    
    if [[ $outermost == "y" ]]; then
        nz_realip_grpc='$remote_addr'
        nz_realip_ws='$remote_addr'
        nz_realip_web='$remote_addr'
    elif [[ $use_cdn == "y" ]]; then
        local hvar=$(echo "$cdn_header" | tr '-' '_' | tr '[:upper:]' '[:lower:]')
        nz_realip_grpc='$http_'"${hvar}"
        nz_realip_ws='$http_'"${hvar}"
        nz_realip_web='$http_'"${hvar}"
    else
        nz_realip_grpc='$remote_addr'
        nz_realip_ws='$remote_addr'
        nz_realip_web='$remote_addr'
    fi

    cat >> "$CONFIG_FILE" << EOF

    location ^~ /proto.NezhaService/ {
        grpc_set_header Host \$host;
        grpc_set_header nz-realip ${nz_realip_grpc};
        grpc_read_timeout 600s;
        grpc_send_timeout 600s;
        grpc_socket_keepalive on;
        client_max_body_size 10m;
        grpc_buffer_size 4m;
        grpc_pass grpc://dashboard;
    }

    location ~* ^/api/v1/ws/(server|terminal|file)(.*)\$ {
        proxy_set_header Host \$host;
        proxy_set_header nz-realip ${nz_realip_ws};
        proxy_set_header Origin https://\$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass http://127.0.0.1:${port};
    }

    location / {
        proxy_set_header Host \$host;
        proxy_set_header nz-realip ${nz_realip_web};
EOF

    if [[ $outermost == "y" ]]; then
        echo "        proxy_set_header X-Forwarded-Proto \$scheme;" >> "$CONFIG_FILE"
    fi

    cat >> "$CONFIG_FILE" << EOF
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        proxy_max_temp_file_size 0;
        proxy_pass http://127.0.0.1:${port};
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    return 301 https://\$host\$request_uri;
}
EOF

    log_info "配置文件: $CONFIG_FILE"
    
    if [[ -n "$ENABLED_FILE" ]]; then
        mkdir -p /etc/nginx/sites-enabled
        ln -sf "$CONFIG_FILE" "$ENABLED_FILE" 2>/dev/null
    fi
}

# 重载 Nginx
reload_nginx() {
    log_step "测试配置..."
    
    if nginx -t > /dev/null 2>&1; then
        log_info "✓ 配置正确"
        systemctl reload nginx
        log_info "✓ Nginx 已重载"
        return 0
    else
        log_error "配置错误"
        nginx -t
        return 1
    fi
}

# 配置防火墙
configure_firewall() {
    log_step "配置防火墙..."
    
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        log_info "✓ UFW 规则已添加"
    elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
        firewall-cmd --permanent --add-service=http > /dev/null 2>&1
        firewall-cmd --permanent --add-service=https > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_info "✓ Firewalld 规则已添加"
    else
        log_warn "请手动开放 80 和 443 端口"
    fi
}

# 显示完成信息
show_completion() {
    local domain=$1
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}         配置完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}访问地址:${NC} ${GREEN}https://${domain}${NC}"
    echo -e "${BLUE}配置文件:${NC} $CONFIG_FILE"
    echo -e "${BLUE}证书路径:${NC} $SSL_CERT"
    echo ""
    echo -e "${YELLOW}提醒:${NC}"
    echo "1. SSL 证书自动续期"
    echo "2. 确保哪吒面板服务运行正常"
    echo "3. CDN 使用完全(严格) SSL 模式"
    echo ""
}

# 读取输入（兼容管道和终端）
read_input() {
    local prompt=$1
    local default=$2
    local result
    
    if [[ -t 0 ]]; then
        # 交互式终端
        read -r -p "$prompt" result
    else
        # 非交互式（从管道）
        echo "$prompt" >&2
        read -r result
    fi
    
    result=$(echo "$result" | xargs)
    echo "${result:-$default}"
}

# 主函数
main() {
    show_banner
    check_root
    detect_os
    install_dependencies
    get_server_ip
    
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}          配置向导${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 输入域名
    DOMAIN=""
    while [[ -z "$DOMAIN" ]]; do
        DOMAIN=$(read_input "请输入域名 (如 dashboard.example.com): " "")
        
        if [[ -z "$DOMAIN" ]]; then
            log_error "域名不能为空"
            continue
        fi
        
        if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'; then
            log_error "域名格式错误"
            DOMAIN=""
            continue
        fi
        
        echo ""
        if check_dns_resolution "$DOMAIN"; then
            break
        fi
        
        echo ""
        continue_choice=$(read_input "域名解析不正确，是否继续? (y/n): " "n")
        if [[ "$continue_choice" == "y" ]]; then
            log_warn "跳过解析检查"
            break
        fi
        DOMAIN=""
    done
    
    echo ""
    NEZHA_PORT=$(read_input "哪吒面板端口 [8008]: " "8008")
    
    echo ""
    echo "SSL 证书:"
    echo "1) 自动申请 (推荐)"
    echo "2) 已有证书"
    ssl_choice=$(read_input "选择 [1]: " "1")
    
    echo ""
    if [[ "$ssl_choice" == "1" ]]; then
        install_acme
        if ! issue_ssl_cert "$DOMAIN"; then
            log_error "证书申请失败"
            exit 1
        fi
    else
        SSL_CERT=$(read_input "证书路径: " "")
        SSL_KEY=$(read_input "私钥路径: " "")
        
        if [[ ! -f "$SSL_CERT" ]] || [[ ! -f "$SSL_KEY" ]]; then
            log_error "证书文件不存在"
            exit 1
        fi
    fi
    
    echo ""
    detect_nginx_version
    
    echo ""
    use_cdn=$(read_input "是否使用 CDN? (y/n) [n]: " "n")
    
    cdn_header="CF-Connecting-IP"
    cdn_range="0.0.0.0/0"
    
    if [[ "$use_cdn" == "y" ]]; then
        echo ""
        echo "1) CloudFlare"
        echo "2) 其他 CDN"
        cdn_type=$(read_input "选择 [1]: " "1")
        
        if [[ "$cdn_type" == "2" ]]; then
            cdn_header=$(read_input "Header 名称: " "CF-Connecting-IP")
            cdn_range=$(read_input "IP 段 [0.0.0.0/0]: " "0.0.0.0/0")
        fi
    fi
    
    echo ""
    outermost=$(read_input "Nginx 是否最外层? (y/n) [n]: " "n")
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    generate_nginx_config "$DOMAIN" "$NEZHA_PORT" "$use_cdn" "$cdn_header" "$cdn_range" "$outermost"
    
    echo ""
    configure_firewall
    
    echo ""
    if reload_nginx; then
        show_completion "$DOMAIN"
    else
        log_error "配置失败"
        exit 1
    fi
}

# 执行
trap 'echo -e "\n${YELLOW}已中断${NC}"; exit 130' INT TERM
main
