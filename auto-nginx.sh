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
    
    # 安装基础工具
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt update -qq
        apt install -y curl socat cron wget dnsutils 2>/dev/null || apt install -y curl socat cron wget bind9-dnsutils
    elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "rocky" ]] || [[ "$OS" == "almalinux" ]]; then
        yum install -y curl socat cronie wget bind-utils -q
    else
        log_error "不支持的操作系统"
        exit 1
    fi
    
    # 检查并安装 Nginx
    if ! command -v nginx &> /dev/null; then
        log_warn "未检测到 Nginx，正在安装..."
        if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
            apt install -y nginx
        else
            yum install -y nginx
        fi
        systemctl enable nginx
        systemctl start nginx
    else
        log_info "Nginx 已安装"
    fi
}

# 获取服务器公网 IP
get_server_ip() {
    log_step "获取服务器公网 IP..."
    SERVER_IP=$(curl -s4m10 ifconfig.me 2>/dev/null || curl -s4m10 icanhazip.com 2>/dev/null || curl -s4m10 api.ipify.org 2>/dev/null)
    
    if [[ -z "$SERVER_IP" ]]; then
        log_error "无法获取服务器公网 IP，请检查网络连接"
        exit 1
    fi
    
    log_info "服务器公网 IP: ${GREEN}${SERVER_IP}${NC}"
}

# 检测域名解析
check_dns_resolution() {
    local domain=$1
    log_step "检测域名 ${domain} 的 DNS 解析..."
    
    # 获取域名解析的 IP（使用多个 DNS 服务器尝试）
    DOMAIN_IP=""
    for dns in "8.8.8.8" "1.1.1.1" "223.5.5.5"; do
        DOMAIN_IP=$(dig +short A "$domain" @${dns} 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
        if [[ -n "$DOMAIN_IP" ]]; then
            break
        fi
    done
    
    if [[ -z "$DOMAIN_IP" ]]; then
        log_error "域名 ${domain} 未解析或解析失败"
        echo -e "  ${YELLOW}请确保：${NC}"
        echo -e "  1. 域名已添加 A 记录"
        echo -e "  2. A 记录指向: ${GREEN}${SERVER_IP}${NC}"
        echo -e "  3. DNS 解析已生效（可能需要等待几分钟）"
        return 1
    fi
    
    log_info "域名解析 IP: ${BLUE}${DOMAIN_IP}${NC}"
    
    # 比对 IP
    if [[ "$DOMAIN_IP" == "$SERVER_IP" ]]; then
        log_info "✓ 域名解析正确，指向本服务器"
        return 0
    else
        log_error "× 域名解析不正确"
        echo -e "  ${RED}域名指向: ${DOMAIN_IP}${NC}"
        echo -e "  ${GREEN}服务器IP: ${SERVER_IP}${NC}"
        echo -e "  ${YELLOW}请先将域名 A 记录解析到服务器 IP: ${SERVER_IP}${NC}"
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
    
    # 安装 acme.sh
    curl -s https://get.acme.sh | sh -s email=admin@example.com > /dev/null 2>&1
    
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log_error "acme.sh 安装失败"
        return 1
    fi
    
    # 设置默认 CA 为 Let's Encrypt
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
    
    log_info "acme.sh 安装完成"
}

# 申请 SSL 证书
issue_ssl_cert() {
    local domain=$1
    local cert_dir="/etc/nginx/ssl/${domain}"
    
    log_step "申请 SSL 证书（使用 standalone 模式）..."
    
    # 创建证书目录
    mkdir -p "$cert_dir"
    
    # 停止 Nginx（避免端口冲突）
    log_info "暂停 Nginx 服务..."
    systemctl stop nginx 2>/dev/null || true
    sleep 2
    
    # 检查 80 端口是否被占用
    if netstat -tuln | grep -q ':80 '; then
        log_error "80 端口被占用，无法申请证书"
        systemctl start nginx 2>/dev/null || true
        return 1
    fi
    
    # 使用 standalone 模式申请证书
    log_info "正在申请证书，请稍候..."
    if ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --keylength ec-256 --force; then
        log_info "✓ 证书申请成功"
    else
        log_error "× 证书申请失败"
        systemctl start nginx 2>/dev/null || true
        return 1
    fi
    
    # 安装证书到指定目录
    log_info "安装证书到 ${cert_dir}"
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --ecc \
        --fullchain-file "${cert_dir}/fullchain.pem" \
        --key-file "${cert_dir}/key.pem" \
        --reloadcmd "systemctl reload nginx" > /dev/null 2>&1
    
    # 设置证书文件权限
    chmod 644 "${cert_dir}/fullchain.pem"
    chmod 600 "${cert_dir}/key.pem"
    
    # 启动 Nginx
    systemctl start nginx
    
    log_info "✓ 证书已安装到: $cert_dir"
    
    # 返回证书路径
    SSL_CERT="${cert_dir}/fullchain.pem"
    SSL_KEY="${cert_dir}/key.pem"
    
    return 0
}

# 检测 Nginx 版本
detect_nginx_version() {
    NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '(?<=nginx/)\d+\.\d+\.\d+')
    log_info "Nginx 版本: $NGINX_VERSION"
    
    MAJOR=$(echo $NGINX_VERSION | cut -d. -f1)
    MINOR=$(echo $NGINX_VERSION | cut -d. -f2)
    PATCH=$(echo $NGINX_VERSION | cut -d. -f3)
    
    USE_NEW_HTTP2=false
    if [[ $MAJOR -gt 1 ]] || [[ $MAJOR -eq 1 && $MINOR -gt 25 ]] || [[ $MAJOR -eq 1 && $MINOR -eq 25 && $PATCH -gt 1 ]]; then
        USE_NEW_HTTP2=true
        log_info "使用新版 HTTP/2 语法"
    fi
}

# 生成 Nginx 配置
generate_nginx_config() {
    local domain=$1
    local nezha_port=$2
    local use_cdn=$3
    local cdn_header=$4
    local cdn_ip_range=$5
    local is_outermost=$6
    
    # 确定配置文件路径
    if [[ -d "/etc/nginx/sites-available" ]]; then
        CONFIG_FILE="/etc/nginx/sites-available/nezha-${domain}.conf"
        ENABLED_FILE="/etc/nginx/sites-enabled/nezha-${domain}.conf"
    else
        mkdir -p /etc/nginx/conf.d
        CONFIG_FILE="/etc/nginx/conf.d/nezha-${domain}.conf"
        ENABLED_FILE=""
    fi
    
    log_step "生成 Nginx 配置文件..."
    
    cat > "$CONFIG_FILE" << EOF
# 哪吒面板反向代理配置
# 域名: ${domain}
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

upstream dashboard {
    server 127.0.0.1:${nezha_port};
    keepalive 512;
}

server {
EOF

    # HTTP2 配置
    if [[ $USE_NEW_HTTP2 == true ]]; then
        cat >> "$CONFIG_FILE" << 'EOF'
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
EOF
    else
        cat >> "$CONFIG_FILE" << 'EOF'
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
EOF
    fi

    cat >> "$CONFIG_FILE" << EOF

    server_name ${domain};
    
    # SSL 配置
    ssl_certificate          ${SSL_CERT};
    ssl_certificate_key      ${SSL_KEY};
    ssl_stapling on;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    underscores_in_headers on;
EOF

    # CDN 配置
    if [[ $use_cdn == "y" ]]; then
        cat >> "$CONFIG_FILE" << EOF
    
    # CDN 真实 IP 配置
    set_real_ip_from ${cdn_ip_range};
    real_ip_header ${cdn_header};
EOF
    fi

    # gRPC 配置
    cat >> "$CONFIG_FILE" << 'EOF'

    # gRPC 配置
    location ^~ /proto.NezhaService/ {
        grpc_set_header Host $host;
EOF

    if [[ $is_outermost == "y" ]]; then
        cat >> "$CONFIG_FILE" << 'EOF'
        grpc_set_header nz-realip $remote_addr;
EOF
    elif [[ $use_cdn == "y" ]]; then
        local header_var=$(echo "$cdn_header" | tr '-' '_' | tr '[:upper:]' '[:lower:]')
        cat >> "$CONFIG_FILE" << EOF
        grpc_set_header nz-realip \$http_${header_var};
EOF
    else
        cat >> "$CONFIG_FILE" << 'EOF'
        grpc_set_header nz-realip $remote_addr;
EOF
    fi

    cat >> "$CONFIG_FILE" << 'EOF'
        grpc_read_timeout 600s;
        grpc_send_timeout 600s;
        grpc_socket_keepalive on;
        client_max_body_size 10m;
        grpc_buffer_size 4m;
        grpc_pass grpc://dashboard;
    }

    # WebSocket 配置
    location ~* ^/api/v1/ws/(server|terminal|file)(.*)$ {
        proxy_set_header Host $host;
EOF

    if [[ $is_outermost == "y" ]]; then
        cat >> "$CONFIG_FILE" << 'EOF'
        proxy_set_header nz-realip $remote_addr;
EOF
    elif [[ $use_cdn == "y" ]]; then
        local header_var=$(echo "$cdn_header" | tr '-' '_' | tr '[:upper:]' '[:lower:]')
        cat >> "$CONFIG_FILE" << EOF
        proxy_set_header nz-realip \$http_${header_var};
EOF
    else
        cat >> "$CONFIG_FILE" << 'EOF'
        proxy_set_header nz-realip $remote_addr;
EOF
    fi

    cat >> "$CONFIG_FILE" << EOF
        proxy_set_header Origin https://\$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_pass http://127.0.0.1:${nezha_port};
    }

    # Web 配置
    location / {
        proxy_set_header Host \$host;
EOF

    if [[ $is_outermost == "y" ]]; then
        cat >> "$CONFIG_FILE" << 'EOF'
        proxy_set_header nz-realip $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
EOF
    elif [[ $use_cdn == "y" ]]; then
        local header_var=$(echo "$cdn_header" | tr '-' '_' | tr '[:upper:]' '[:lower:]')
        cat >> "$CONFIG_FILE" << EOF
        proxy_set_header nz-realip \$http_${header_var};
EOF
    else
        cat >> "$CONFIG_FILE" << 'EOF'
        proxy_set_header nz-realip $remote_addr;
EOF
    fi

    cat >> "$CONFIG_FILE" << EOF
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        proxy_max_temp_file_size 0;
        proxy_pass http://127.0.0.1:${nezha_port};
    }
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    return 301 https://\$server_name\$request_uri;
}
EOF

    log_info "✓ 配置文件已生成: $CONFIG_FILE"
    
    # 创建软链接
    if [[ -n "$ENABLED_FILE" ]]; then
        mkdir -p /etc/nginx/sites-enabled
        ln -sf "$CONFIG_FILE" "$ENABLED_FILE" 2>/dev/null || true
        log_info "✓ 已创建软链接"
    fi
}

# 测试并重载 Nginx
reload_nginx() {
    log_step "测试 Nginx 配置..."
    
    if nginx -t 2>&1 | grep -q "successful"; then
        log_info "✓ 配置测试通过"
        systemctl reload nginx
        log_info "✓ Nginx 已重载"
        return 0
    else
        log_error "× 配置测试失败"
        nginx -t
        return 1
    fi
}

# 配置防火墙
configure_firewall() {
    log_step "配置防火墙..."
    
    # 检查防火墙类型
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        log_info "✓ UFW 防火墙规则已添加"
    elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
        firewall-cmd --permanent --add-service=http > /dev/null 2>&1
        firewall-cmd --permanent --add-service=https > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_info "✓ Firewalld 防火墙规则已添加"
    else
        log_warn "未检测到活动的防火墙，请手动确保 80 和 443 端口已开放"
    fi
}

# 显示完成信息
show_completion_info() {
    local domain=$1
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}         配置完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${BLUE}面板访问地址:${NC} ${GREEN}https://${domain}${NC}"
    echo -e "${BLUE}配置文件位置:${NC} $CONFIG_FILE"
    echo -e "${BLUE}SSL 证书路径:${NC} $SSL_CERT"
    echo -e "${BLUE}SSL 私钥路径:${NC} $SSL_KEY"
    echo ""
    echo -e "${YELLOW}重要提醒:${NC}"
    echo "1. SSL 证书会自动续期（acme.sh 定时任务）"
    echo "2. 确保哪吒面板服务正在运行在端口 ${NEZHA_PORT}"
    echo "3. 如使用 CDN，请在 CDN 控制台设置 SSL/TLS 模式为【完全】或【完全(严格)】"
    echo "4. 证书续期后会自动重载 Nginx"
    echo "5. 可以使用命令查看证书信息: ~/.acme.sh/acme.sh --info -d ${domain}"
    echo ""
}

# 主函数
main() {
    show_banner
    check_root
    detect_os
    install_dependencies
    get_server_ip
    
    # 收集用户输入
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}          配置信息输入${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # 域名输入和验证
    DOMAIN=""
    while true; do
        read -p "请输入面板域名 (例: dashboard.example.com): " input_domain
        
        if [[ -z "$input_domain" ]]; then
            log_error "域名不能为空，请重新输入"
            continue
        fi
        
        # 验证域名格式
        if ! echo "$input_domain" | grep -qE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'; then
            log_error "域名格式不正确，请重新输入"
            continue
        fi
        
        DOMAIN="$input_domain"
        echo ""
        
        # 检测域名解析
        if check_dns_resolution "$DOMAIN"; then
            echo ""
            break
        else
            echo ""
            read -p "域名解析检查失败，是否继续配置? (y/n): " continue_anyway
            if [[ $continue_anyway == "y" || $continue_anyway == "Y" ]]; then
                log_warn "跳过域名解析检查，继续执行..."
                echo ""
                break
            else
                echo ""
                log_info "请配置好域名解析后重新运行脚本"
                echo ""
            fi
        fi
    done
    
    # 哪吒面板端口
    read -p "哪吒面板运行端口 [默认: 8008]: " NEZHA_PORT
    NEZHA_PORT=${NEZHA_PORT:-8008}
    echo ""
    
    # SSL 证书选项
    echo -e "${YELLOW}SSL 证书配置:${NC}"
    echo "1) 使用 acme.sh 自动申请 Let's Encrypt 证书 (推荐)"
    echo "2) 使用已有证书"
    read -p "请选择 [默认: 1]: " SSL_CHOICE
    SSL_CHOICE=${SSL_CHOICE:-1}
    echo ""
    
    if [[ $SSL_CHOICE == "1" ]]; then
        install_acme
        if ! issue_ssl_cert "$DOMAIN"; then
            log_error "证书申请失败，脚本终止"
            exit 1
        fi
    else
        read -p "SSL 证书完整链路径: " SSL_CERT
        read -p "SSL 证书私钥路径: " SSL_KEY
        echo ""
        
        if [[ ! -f "$SSL_CERT" ]]; then
            log_error "证书文件不存在: $SSL_CERT"
            exit 1
        fi
        
        if [[ ! -f "$SSL_KEY" ]]; then
            log_error "私钥文件不存在: $SSL_KEY"
            exit 1
        fi
        
        log_info "证书文件验证通过"
    fi
    
    # 检测 Nginx 版本
    echo ""
    detect_nginx_version
    echo ""
    
    # CDN 配置
    echo -e "${YELLOW}CDN 配置:${NC}"
    read -p "是否使用 CDN (如 CloudFlare)? (y/n) [默认: n]: " USE_CDN
    USE_CDN=${USE_CDN:-n}
    echo ""
    
    CDN_HEADER="CF-Connecting-IP"
    CDN_IP_RANGE="0.0.0.0/0"
    
    if [[ $USE_CDN == "y" || $USE_CDN == "Y" ]]; then
        echo "CDN 类型:"
        echo "1) CloudFlare"
        echo "2) 其他 CDN (自定义配置)"
        read -p "请选择 [默认: 1]: " CDN_TYPE
        CDN_TYPE=${CDN_TYPE:-1}
        echo ""
        
        if [[ $CDN_TYPE == "2" ]]; then
            read -p "CDN 真实 IP Header 名称: " CDN_HEADER
            read -p "CDN 回源 IP 段 [默认: 0.0.0.0/0]: " input_range
            CDN_IP_RANGE=${input_range:-0.0.0.0/0}
            echo ""
        fi
    fi
    
    # 是否为最外层
    read -p "Nginx 是否为最外层（前面没有其他反向代理）? (y/n) [默认: n]: " IS_OUTERMOST
    IS_OUTERMOST=${IS_OUTERMOST:-n}
    echo ""
    
    # 生成配置
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}          开始配置${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    generate_nginx_config "$DOMAIN" "$NEZHA_PORT" "$USE_CDN" "$CDN_HEADER" "$CDN_IP_RANGE" "$IS_OUTERMOST"
    
    echo ""
    configure_firewall
    
    echo ""
    if reload_nginx; then
        show_completion_info "$DOMAIN"
    else
        log_error "Nginx 配置失败，请检查错误信息"
        echo ""
        echo "配置文件位置: $CONFIG_FILE"
        echo "可以手动检查并修复配置文件"
        exit 1
    fi
}

# 捕获退出信号
trap 'echo -e "\n${YELLOW}脚本已中断${NC}"; exit 130' INT TERM

# 执行主函数
main
