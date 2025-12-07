#!/bin/bash
#
# LNMP Stack Manager for Debian
# Installs and manages Nginx, MariaDB, PHP with interactive TUI
#
# Version: 1.0.0
# Author: LNMP Manager
#

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

PHP_VERSION="8.5"
NGINX_DEB_URL="https://github.com/maulvi/nginx/releases/download/v1.28.0/nginx_1.28.0-openssl3.6.0_amd64.deb"
MARIADB_VERSION="11.8"
WEB_ROOT="/var/www"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║     ██╗     ███╗   ██╗███╗   ███╗██████╗                      ║"
    echo "║     ██║     ████╗  ██║████╗ ████║██╔══██╗                     ║"
    echo "║     ██║     ██╔██╗ ██║██╔████╔██║██████╔╝                     ║"
    echo "║     ██║     ██║╚██╗██║██║╚██╔╝██║██╔═══╝                      ║"
    echo "║     ███████╗██║ ╚████║██║ ╚═╝ ██║██║                          ║"
    echo "║     ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝                          ║"
    echo "║                                                               ║"
    echo "║           Linux • Nginx • MariaDB • PHP Stack                 ║"
    echo "║                     Manager for Debian                        ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

msg_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

msg_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

msg_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

msg_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        msg_error "This script must be run as root"
        exit 1
    fi
}

check_debian() {
    if ! grep -q "debian" /etc/os-release 2>/dev/null; then
        msg_warning "This script is designed for Debian. Proceeding anyway..."
    fi
}

check_whiptail() {
    if ! command -v whiptail &> /dev/null; then
        msg_info "Installing whiptail..."
        apt-get update -qq
        apt-get install -y whiptail
    fi
}

press_enter() {
    echo ""
    read -p "Press Enter to continue..."
}

# ============================================================================
# LOGGING & VALIDATION FUNCTIONS
# ============================================================================

LOG_FILE="/var/log/lnmp-manager.log"

log_action() {
    local action="$1"
    local details="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [$(whoami)] ${action}: ${details}" >> "$LOG_FILE"
}

validate_domain() {
    local domain="$1"
    
    # Check if empty
    if [[ -z "$domain" ]]; then
        msg_error "Domain tidak boleh kosong"
        return 1
    fi
    
    # Check valid domain format
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        msg_error "Format domain tidak valid: $domain"
        return 1
    fi
    
    # Check if site already exists
    if [[ -f "${NGINX_SITES_AVAILABLE}/${domain}" ]]; then
        msg_error "Site '${domain}' sudah ada"
        return 1
    fi
    
    return 0
}

validate_backend() {
    local backend="$1"
    
    # Check format IP:port or localhost:port
    if ! [[ "$backend" =~ ^[a-zA-Z0-9.-]+:[0-9]+$ ]]; then
        msg_error "Format backend tidak valid. Gunakan: IP:port atau hostname:port"
        return 1
    fi
    
    return 0
}

backup_config() {
    local config_file="$1"
    local backup_dir="/var/backups/lnmp"
    
    if [[ -f "$config_file" ]]; then
        mkdir -p "$backup_dir"
        local backup_name=$(basename "$config_file").$(date +%Y%m%d%H%M%S).bak
        cp "$config_file" "${backup_dir}/${backup_name}"
        log_action "BACKUP" "Created backup: ${backup_dir}/${backup_name}"
    fi
}

read_password_secure() {
    local prompt="$1"
    local password=""
    
    # Use whiptail if available for better UX
    if command -v whiptail &> /dev/null; then
        password=$(whiptail --title "Password" --passwordbox "$prompt" 10 50 3>&1 1>&2 2>&3)
    else
        read -s -p "$prompt: " password
        echo ""
    fi
    
    echo "$password"
}

check_swap() {
    local swap_size=$(free -m | awk '/^Swap:/ {print $2}')
    
    if [[ "$swap_size" -eq 0 ]]; then
        msg_warning "Tidak ada swap memory!"
        return 1
    fi
    
    return 0
}

create_swap() {
    local size_gb="${1:-2}"
    local swap_file="/swapfile"
    
    if [[ -f "$swap_file" ]]; then
        msg_warning "Swap file sudah ada"
        return 0
    fi
    
    msg_info "Membuat swap ${size_gb}GB..."
    
    fallocate -l ${size_gb}G "$swap_file"
    chmod 600 "$swap_file"
    mkswap "$swap_file"
    swapon "$swap_file"
    
    # Add to fstab if not already there
    if ! grep -q "$swap_file" /etc/fstab; then
        echo "${swap_file} none swap sw 0 0" >> /etc/fstab
    fi
    
    log_action "SWAP" "Created ${size_gb}GB swap at ${swap_file}"
    msg_success "Swap ${size_gb}GB berhasil dibuat"
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

install_prerequisites() {
    msg_info "Installing prerequisites..."
    apt-get update
    # Note: software-properties-common not available in Debian 13+
    apt-get install -y apt-transport-https curl gnupg2 ca-certificates lsb-release wget
    msg_success "Prerequisites installed"
}

install_php() {
    msg_info "Installing PHP ${PHP_VERSION} from Sury repository..."
    
    # Add Sury repository
    curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb
    dpkg -i /tmp/debsuryorg-archive-keyring.deb
    rm -f /tmp/debsuryorg-archive-keyring.deb
    
    echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/sury-php.list
    
    apt-get update
    
    # Install PHP and extensions
    apt-get install -y \
        php${PHP_VERSION} \
        php${PHP_VERSION}-fpm \
        php${PHP_VERSION}-cli \
        php${PHP_VERSION}-common \
        php${PHP_VERSION}-mysql \
        php${PHP_VERSION}-curl \
        php${PHP_VERSION}-gd \
        php${PHP_VERSION}-mbstring \
        php${PHP_VERSION}-xml \
        php${PHP_VERSION}-zip \
        php${PHP_VERSION}-intl \
        php${PHP_VERSION}-soap \
        php${PHP_VERSION}-bcmath \
        php${PHP_VERSION}-redis \
        php${PHP_VERSION}-readline \
        php${PHP_VERSION}-sqlite3
    
    # Enable and start PHP-FPM
    systemctl enable php${PHP_VERSION}-fpm
    systemctl start php${PHP_VERSION}-fpm
    
    msg_success "PHP ${PHP_VERSION} installed and PHP-FPM enabled"
}

install_nginx() {
    msg_info "Installing Nginx from custom package..."
    
    # Download and install custom nginx
    wget -O /tmp/nginx.deb "${NGINX_DEB_URL}"
    dpkg -i /tmp/nginx.deb || apt-get install -f -y
    rm -f /tmp/nginx.deb
    
    # Create sites directories if not exist
    mkdir -p ${NGINX_SITES_AVAILABLE}
    mkdir -p ${NGINX_SITES_ENABLED}
    
    # Check if nginx.conf includes sites-enabled
    if ! grep -q "sites-enabled" /etc/nginx/nginx.conf; then
        # Add include directive before the last closing brace
        sed -i '/^}/i\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
    fi
    
    # Enable and start nginx
    systemctl enable nginx
    systemctl start nginx
    
    msg_success "Nginx installed and enabled"
}

install_mariadb() {
    local root_password="$1"
    
    msg_info "Installing MariaDB ${MARIADB_VERSION}..."
    
    # Import MariaDB key
    mkdir -p /etc/apt/keyrings
    curl -o /etc/apt/keyrings/mariadb-keyring.pgp 'https://mariadb.org/mariadb_release_signing_key.pgp'
    
    # Add MariaDB repository
    cat > /etc/apt/sources.list.d/mariadb.sources << EOF
# MariaDB ${MARIADB_VERSION} repository
X-Repolib-Name: MariaDB
Types: deb
URIs: http://mariadb.mirrors.ovh.net/MariaDB/repo/${MARIADB_VERSION}/debian
Suites: $(lsb_release -sc)
Components: main
Signed-By: /etc/apt/keyrings/mariadb-keyring.pgp
EOF
    
    apt-get update
    apt-get install -y mariadb-server mariadb-client
    
    # Enable and start MariaDB
    systemctl enable mariadb
    systemctl start mariadb
    
    # Set root password if provided
    if [[ -n "$root_password" ]]; then
        msg_info "Setting MariaDB root password..."
        mariadb -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${root_password}';"
        mariadb -e "FLUSH PRIVILEGES;"
        msg_success "MariaDB root password set"
    fi
    
    msg_success "MariaDB ${MARIADB_VERSION} installed and enabled"
    
    if [[ -z "$root_password" ]]; then
        msg_info "Run 'mariadb-secure-installation' to set root password and secure installation"
    fi
}

# Interactive MariaDB installation with password prompt
install_mariadb_interactive() {
    local password=""
    
    if whiptail --title "MariaDB Root Password" --yesno "Apakah Anda ingin mengatur password root MariaDB sekarang?\n\n(Jika tidak, Anda bisa set nanti dengan mariadb-secure-installation)" 12 60; then
        password=$(whiptail --title "MariaDB Root Password" --passwordbox "Masukkan password root MariaDB:" 10 50 3>&1 1>&2 2>&3)
        
        if [[ -n "$password" ]]; then
            local password_confirm
            password_confirm=$(whiptail --title "Konfirmasi Password" --passwordbox "Konfirmasi password:" 10 50 3>&1 1>&2 2>&3)
            
            if [[ "$password" != "$password_confirm" ]]; then
                msg_error "Password tidak cocok! Instalasi tetap dilanjutkan tanpa set password."
                password=""
            fi
        fi
    fi
    
    install_mariadb "$password"
}

install_certbot() {
    msg_info "Installing Certbot..."
    
    apt-get install -y certbot python3-certbot-nginx
    
    msg_success "Certbot installed"
}

install_redis() {
    msg_info "Installing Redis server from official repository..."
    
    # Install prerequisites
    apt-get install -y lsb-release curl gpg
    
    # Add Redis repository key
    curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
    chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
    
    # Add Redis repository
    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" > /etc/apt/sources.list.d/redis.list
    
    apt-get update
    apt-get install -y redis
    
    # Enable and start Redis
    systemctl enable redis-server
    systemctl start redis-server
    
    msg_success "Redis server installed and enabled"
    msg_info "Test connection with: redis-cli ping"
    log_action "INSTALL" "Redis server installed"
}

# UFW Firewall Configuration
install_ufw() {
    msg_info "Installing and configuring UFW firewall..."
    
    apt-get install -y ufw
    
    # Detect SSH port from sshd_config
    local ssh_port=22
    if [[ -f /etc/ssh/sshd_config ]]; then
        local detected_port=$(grep -E "^Port\s+" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
        if [[ -n "$detected_port" && "$detected_port" =~ ^[0-9]+$ ]]; then
            ssh_port=$detected_port
        fi
    fi
    
    # Also check currently listening SSH port
    local listening_ssh=$(ss -tlnp | grep sshd | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    if [[ -n "$listening_ssh" && "$listening_ssh" != "$ssh_port" ]]; then
        msg_warning "SSH mungkin berjalan di port ${listening_ssh}, bukan ${ssh_port}"
        ssh_port=$listening_ssh
    fi
    
    msg_info "SSH port detected: ${ssh_port}"
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow detected SSH port (IMPORTANT - do this first!)
    ufw allow ${ssh_port}/tcp comment 'SSH'
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Check for other common services that might be running
    echo ""
    msg_info "Checking listening services..."
    
    # Check if any other important services are listening
    local listening_ports=$(ss -tlnp | grep -E "LISTEN" | awk '{print $4}' | grep -oE '[0-9]+$' | sort -u)
    local allowed_ports="${ssh_port} 80 443"
    
    for port in $listening_ports; do
        # Skip already allowed ports
        if [[ " $allowed_ports " =~ " $port " ]]; then
            continue
        fi
        
        # Get process name for this port
        local process=$(ss -tlnp | grep ":${port}" | grep -oP '(?<=users:\(\(")[^"]+' | head -1)
        
        # Skip internal services (mariadb, redis should only be local)
        case "$process" in
            mysqld|mariadbd|redis-server)
                # These should only be local - don't expose
                continue
                ;;
        esac
        
        # For other services, ask if should be allowed
        if [[ -n "$process" ]]; then
            echo -e "  ${YELLOW}!${NC} Port ${port} (${process}) is listening"
        fi
    done
    
    # Confirmation before enabling
    echo ""
    msg_warning "UFW akan mengaktifkan firewall dengan rules berikut:"
    echo -e "  ${GREEN}ALLOW${NC} SSH (port ${ssh_port})"
    echo -e "  ${GREEN}ALLOW${NC} HTTP (port 80)"
    echo -e "  ${GREEN}ALLOW${NC} HTTPS (port 443)"
    echo -e "  ${RED}DENY${NC} Semua port lainnya dari luar"
    echo ""
    
    read -p "Lanjutkan? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        msg_warning "UFW installation cancelled"
        return 1
    fi
    
    # Enable UFW
    echo "y" | ufw enable
    
    log_action "FIREWALL" "UFW installed - SSH port ${ssh_port}, HTTP, HTTPS"
    msg_success "UFW firewall configured"
    echo ""
    echo -e "${CYAN}Ports yang dibuka:${NC}"
    echo "  • SSH (${ssh_port})"
    echo "  • HTTP (80)"
    echo "  • HTTPS (443)"
    echo ""
    echo -e "${YELLOW}Catatan:${NC}"
    echo "  • MariaDB (3306) dan Redis (6379) hanya lokal"
    echo "  • Untuk membuka port lain: ufw allow <port>/tcp"
    echo ""
}

# Fail2ban Installation
install_fail2ban() {
    msg_info "Installing fail2ban..."
    
    apt-get install -y fail2ban
    
    # Create local config
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_action "SECURITY" "Fail2ban installed and configured"
    msg_success "Fail2ban installed"
    echo ""
    echo -e "${CYAN}Perlindungan aktif:${NC}"
    echo "  • SSH brute force (max 3 attempts)"
    echo "  • Nginx auth failures"
    echo "  • Nginx rate limit violations"
}

# OPcache Configuration
configure_opcache() {
    msg_info "Configuring PHP OPcache..."
    
    local opcache_conf="/etc/php/${PHP_VERSION}/fpm/conf.d/10-opcache.ini"
    
    backup_config "$opcache_conf"
    
    # Calculate optimal values based on RAM
    local total_ram=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    local opcache_memory=128
    
    if [[ $total_ram -gt 4096 ]]; then
        opcache_memory=256
    elif [[ $total_ram -gt 2048 ]]; then
        opcache_memory=192
    fi
    
    cat > "$opcache_conf" << EOF
; OPcache Configuration - Optimized by LNMP Manager
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=${opcache_memory}
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.max_wasted_percentage=10
opcache.validate_timestamps=1
opcache.revalidate_freq=2
opcache.save_comments=1
opcache.fast_shutdown=1
EOF

    systemctl restart php${PHP_VERSION}-fpm
    
    log_action "CONFIG" "OPcache configured with ${opcache_memory}MB"
    msg_success "OPcache configured (${opcache_memory}MB)"
}

# Nginx Worker Tuning
configure_nginx_workers() {
    msg_info "Configuring Nginx workers..."
    
    local nginx_conf="/etc/nginx/nginx.conf"
    backup_config "$nginx_conf"
    
    local cpu_cores=$(nproc)
    local worker_connections=1024
    
    # 2048 connections per core for servers with more RAM
    local total_ram=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ $total_ram -gt 2048 ]]; then
        worker_connections=2048
    fi
    
    # Update worker_processes
    sed -i "s/worker_processes.*/worker_processes auto;/" "$nginx_conf"
    
    # Update worker_connections if exists
    if grep -q "worker_connections" "$nginx_conf"; then
        sed -i "s/worker_connections.*/worker_connections ${worker_connections};/" "$nginx_conf"
    fi
    
    nginx -t && systemctl reload nginx
    
    log_action "CONFIG" "Nginx workers configured: auto processes, ${worker_connections} connections"
    msg_success "Nginx workers configured (${cpu_cores} cores, ${worker_connections} connections)"
}

# Database Management
create_database() {
    local db_name="$1"
    local db_user="$2"
    local db_pass="$3"
    
    if [[ -z "$db_name" || -z "$db_user" || -z "$db_pass" ]]; then
        msg_error "Usage: create_database <db_name> <db_user> <db_pass>"
        return 1
    fi
    
    msg_info "Creating database '${db_name}' and user '${db_user}'..."
    
    mariadb -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mariadb -e "CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';"
    mariadb -e "GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';"
    mariadb -e "FLUSH PRIVILEGES;"
    
    log_action "DATABASE" "Created database '${db_name}' with user '${db_user}'"
    msg_success "Database '${db_name}' created with user '${db_user}'"
}

create_database_interactive() {
    local db_name=$(whiptail --title "Create Database" --inputbox "Nama database:" 10 50 3>&1 1>&2 2>&3)
    [[ -z "$db_name" ]] && return
    
    local db_user=$(whiptail --title "Create Database" --inputbox "Username:" 10 50 "$db_name" 3>&1 1>&2 2>&3)
    [[ -z "$db_user" ]] && return
    
    local db_pass=$(whiptail --title "Create Database" --passwordbox "Password:" 10 50 3>&1 1>&2 2>&3)
    [[ -z "$db_pass" ]] && return
    
    create_database "$db_name" "$db_user" "$db_pass"
}

# Log Rotation
configure_logrotate() {
    msg_info "Configuring log rotation..."
    
    cat > /etc/logrotate.d/lnmp << 'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}

/var/log/lnmp-manager.log {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF

    log_action "CONFIG" "Log rotation configured"
    msg_success "Log rotation configured"
}

# Health Check Endpoint
create_health_endpoint() {
    local domain="$1"
    local doc_root="${WEB_ROOT}/${domain}"
    
    if [[ ! -d "$doc_root" ]]; then
        msg_error "Document root tidak ditemukan: $doc_root"
        return 1
    fi
    
    cat > "${doc_root}/health.php" << 'EOF'
<?php
header('Content-Type: application/json');

$health = [
    'status' => 'ok',
    'timestamp' => date('c'),
    'checks' => []
];

// PHP check
$health['checks']['php'] = 'ok';

// MariaDB check
try {
    $pdo = new PDO('mysql:host=localhost', 'root', '');
    $health['checks']['mariadb'] = 'ok';
} catch (Exception $e) {
    $health['checks']['mariadb'] = 'error';
    $health['status'] = 'degraded';
}

// Redis check
if (class_exists('Redis')) {
    try {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379);
        $health['checks']['redis'] = $redis->ping() ? 'ok' : 'error';
    } catch (Exception $e) {
        $health['checks']['redis'] = 'error';
        $health['status'] = 'degraded';
    }
} else {
    $health['checks']['redis'] = 'not_installed';
}

http_response_code($health['status'] === 'ok' ? 200 : 503);
echo json_encode($health, JSON_PRETTY_PRINT);
EOF

    log_action "HEALTH" "Created health endpoint for ${domain}"
    msg_success "Health check endpoint created: ${domain}/health.php"
}

# SSL Auto-Renewal Check
check_ssl_renewal() {
    msg_info "Checking SSL auto-renewal status..."
    
    if systemctl is-active --quiet certbot.timer; then
        msg_success "Certbot timer is active"
    else
        msg_warning "Certbot timer is not active!"
        systemctl enable certbot.timer
        systemctl start certbot.timer
        msg_success "Certbot timer activated"
    fi
    
    # Test renewal
    certbot renew --dry-run 2>/dev/null
    if [[ $? -eq 0 ]]; then
        msg_success "SSL renewal test passed"
    else
        msg_warning "SSL renewal test failed - check certbot configuration"
    fi
}

install_all() {
    msg_info "Starting full LNMP stack installation..."
    
    # Check and create swap if needed
    if ! check_swap; then
        if whiptail --title "Swap Memory" --yesno "Tidak ada swap. Buat swap 2GB?" 8 40 2>/dev/null; then
            create_swap 2
        fi
    fi
    
    install_prerequisites
    install_php
    install_nginx
    install_mariadb
    install_redis
    install_certbot
    install_ufw
    install_fail2ban
    
    echo ""
    msg_info "Configuring optimizations..."
    configure_opcache
    configure_nginx_workers
    configure_logrotate
    
    echo ""
    msg_info "Applying security hardening (safe mode)..."
    harden_all
    
    log_action "INSTALL" "Full LNMP stack installation completed"
    msg_success "LNMP stack installation complete with security hardening!"
}

# ============================================================================
# SITE MANAGEMENT FUNCTIONS
# ============================================================================

create_php_site() {
    local domain=$1
    local enable_ssl=$2
    
    # Validate domain
    if [[ -z "$domain" ]]; then
        msg_error "Domain name is required"
        return 1
    fi
    
    # Check if site already exists
    if [[ -f "${NGINX_SITES_AVAILABLE}/${domain}" ]]; then
        msg_error "Site '${domain}' sudah ada"
        return 1
    fi
    
    local site_root="${WEB_ROOT}/${domain}"
    local config_file="${NGINX_SITES_AVAILABLE}/${domain}"
    
    # Create document root
    mkdir -p "${site_root}/public"
    
    # Create default index.php
    cat > "${site_root}/public/index.php" << 'EOF'
<?php
phpinfo();
EOF
    
    # Set permissions
    chown -R www-data:www-data "${site_root}"
    chmod -R 755 "${site_root}"
    
    # Create Nginx config
    cat > "${config_file}" << EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name ${domain} www.${domain};
    root ${site_root}/public;
    index index.php index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
}
EOF
    
    # Enable site
    ln -sf "${config_file}" "${NGINX_SITES_ENABLED}/${domain}"
    
    # Test and reload nginx
    nginx -t && systemctl reload nginx
    
    msg_success "PHP site '${domain}' created at ${site_root}"
    
    # Setup SSL if requested
    if [[ "$enable_ssl" == "true" || "$enable_ssl" == "--ssl" ]]; then
        setup_ssl "$domain"
    fi
}

create_proxy_site() {
    local domain=$1
    local backend=$2
    local enable_ssl=$3
    
    if [[ -z "$domain" ]]; then
        msg_error "Domain name is required"
        return 1
    fi
    
    if [[ -z "$backend" ]]; then
        msg_error "Backend address (IP:port) is required"
        return 1
    fi
    
    local config_file="${NGINX_SITES_AVAILABLE}/${domain}"
    
    # Create Nginx config for reverse proxy
    cat > "${config_file}" << EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name ${domain} www.${domain};
    
    location / {
        proxy_pass http://${backend};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 86400;
    }
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log;
}
EOF
    
    # Enable site
    ln -sf "${config_file}" "${NGINX_SITES_ENABLED}/${domain}"
    
    # Test and reload nginx
    nginx -t && systemctl reload nginx
    
    msg_success "Reverse proxy site '${domain}' -> '${backend}' created"
    
    # Setup SSL if requested
    if [[ "$enable_ssl" == "true" || "$enable_ssl" == "--ssl" ]]; then
        setup_ssl "$domain"
    fi
}

delete_site() {
    local domain=$1
    
    if [[ -z "$domain" ]]; then
        msg_error "Domain name is required"
        return 1
    fi
    
    # Remove config files
    rm -f "${NGINX_SITES_ENABLED}/${domain}"
    rm -f "${NGINX_SITES_AVAILABLE}/${domain}"
    
    # Optionally remove site files
    if [[ -d "${WEB_ROOT}/${domain}" ]]; then
        read -p "Delete site files at ${WEB_ROOT}/${domain}? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "${WEB_ROOT}/${domain}"
            msg_info "Site files deleted"
        fi
    fi
    
    nginx -t && systemctl reload nginx
    
    msg_success "Site '${domain}' deleted"
}

enable_site() {
    local domain=$1
    
    if [[ ! -f "${NGINX_SITES_AVAILABLE}/${domain}" ]]; then
        msg_error "Site '${domain}' not found"
        return 1
    fi
    
    ln -sf "${NGINX_SITES_AVAILABLE}/${domain}" "${NGINX_SITES_ENABLED}/${domain}"
    nginx -t && systemctl reload nginx
    
    msg_success "Site '${domain}' enabled"
}

disable_site() {
    local domain=$1
    
    rm -f "${NGINX_SITES_ENABLED}/${domain}"
    nginx -t && systemctl reload nginx
    
    msg_success "Site '${domain}' disabled"
}

list_sites() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                      CONFIGURED SITES                         ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [[ -d "${NGINX_SITES_AVAILABLE}" ]]; then
        for site in ${NGINX_SITES_AVAILABLE}/*; do
            if [[ -f "$site" ]]; then
                local name=$(basename "$site")
                local status="disabled"
                
                if [[ -L "${NGINX_SITES_ENABLED}/${name}" ]]; then
                    status="enabled"
                fi
                
                # Check site type
                local type="php"
                if grep -q "proxy_pass" "$site"; then
                    type="proxy"
                fi
                
                # Check SSL expiry date
                local ssl_expiry="-"
                local cert_file="/etc/letsencrypt/live/${name}/fullchain.pem"
                
                if [[ -f "$cert_file" ]]; then
                    ssl_expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2 | xargs -I{} date -d "{}" "+%Y-%m-%d" 2>/dev/null)
                    [[ -z "$ssl_expiry" ]] && ssl_expiry="error"
                fi
                
                echo -e "  ${BLUE}•${NC} ${name} [${type}] - ${status} - SSL: ${ssl_expiry}"
            fi
        done
    else
        echo "  No sites configured"
    fi
    
    echo ""
}

setup_ssl() {
    local domain=$1
    local email=$2
    
    if [[ -z "$domain" ]]; then
        msg_error "Domain name is required"
        return 1
    fi
    
    if [[ -z "$email" ]]; then
        certbot --nginx -d "$domain" -d "www.${domain}" --register-unsafely-without-email --agree-tos
    else
        certbot --nginx -d "$domain" -d "www.${domain}" --email "$email" --agree-tos --no-eff-email
    fi
    
    msg_success "SSL certificate obtained for '${domain}'"
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

service_action() {
    local service=$1
    local action=$2
    
    case $service in
        nginx)
            systemctl $action nginx
            ;;
        php|php-fpm)
            systemctl $action php${PHP_VERSION}-fpm
            ;;
        mariadb|mysql)
            systemctl $action mariadb
            ;;
        redis)
            systemctl $action redis-server
            ;;
        *)
            msg_error "Unknown service: $service"
            return 1
            ;;
    esac
    
    msg_success "${service} ${action}ed"
}

show_status() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                      SERVICE STATUS                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Nginx status
    if systemctl is-active --quiet nginx; then
        echo -e "  ${GREEN}●${NC} Nginx: ${GREEN}running${NC}"
        nginx -v 2>&1 | sed 's/^/    /'
    else
        echo -e "  ${RED}●${NC} Nginx: ${RED}stopped${NC}"
    fi
    
    echo ""
    
    # PHP-FPM status
    if systemctl is-active --quiet php${PHP_VERSION}-fpm 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} PHP-FPM ${PHP_VERSION}: ${GREEN}running${NC}"
        php -v 2>&1 | head -1 | sed 's/^/    /'
    else
        echo -e "  ${RED}●${NC} PHP-FPM ${PHP_VERSION}: ${RED}stopped/not installed${NC}"
    fi
    
    echo ""
    
    # MariaDB status
    if systemctl is-active --quiet mariadb; then
        echo -e "  ${GREEN}●${NC} MariaDB: ${GREEN}running${NC}"
        mariadb --version 2>&1 | sed 's/^/    /'
    else
        echo -e "  ${RED}●${NC} MariaDB: ${RED}stopped/not installed${NC}"
    fi
    
    echo ""
    
    # Redis status
    if systemctl is-active --quiet redis-server; then
        echo -e "  ${GREEN}●${NC} Redis: ${GREEN}running${NC}"
        redis-server --version 2>&1 | sed 's/^/    /'
    else
        echo -e "  ${RED}●${NC} Redis: ${RED}stopped/not installed${NC}"
    fi
    
    echo ""
}

# ============================================================================
# CONFIGURATION MANAGEMENT FUNCTIONS
# ============================================================================

get_total_ram_mb() {
    awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo
}

get_cpu_cores() {
    nproc
}

# PHP-FPM Configuration
configure_php_fpm() {
    local pool_conf="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
    
    if [[ ! -f "$pool_conf" ]]; then
        msg_error "PHP-FPM pool config not found: $pool_conf"
        return 1
    fi
    
    local total_ram=$(get_total_ram_mb)
    local cpu_cores=$(get_cpu_cores)
    
    msg_info "System: ${total_ram}MB RAM, ${cpu_cores} CPU cores"
    
    # Calculate recommended values
    # Average PHP process uses ~50-100MB, we'll use 80MB as average
    local php_mem_per_process=80
    local available_ram=$((total_ram * 70 / 100))  # Use 70% of RAM for PHP
    local recommended_max=$((available_ram / php_mem_per_process))
    local recommended_start=$((recommended_max / 4))
    local recommended_min=$((recommended_max / 8))
    local recommended_spare=$((recommended_max / 2))
    
    echo ""
    echo -e "${CYAN}Current PHP-FPM Pool Configuration:${NC}"
    echo "  pm = $(grep -E '^pm\s*=' "$pool_conf" | awk -F'=' '{print $2}' | xargs)"
    echo "  pm.max_children = $(grep -E '^pm\.max_children' "$pool_conf" | awk -F'=' '{print $2}' | xargs)"
    echo "  pm.start_servers = $(grep -E '^pm\.start_servers' "$pool_conf" | awk -F'=' '{print $2}' | xargs)"
    echo "  pm.min_spare_servers = $(grep -E '^pm\.min_spare_servers' "$pool_conf" | awk -F'=' '{print $2}' | xargs)"
    echo "  pm.max_spare_servers = $(grep -E '^pm\.max_spare_servers' "$pool_conf" | awk -F'=' '{print $2}' | xargs)"
    echo ""
    echo -e "${YELLOW}Recommended values for your system:${NC}"
    echo "  pm.max_children = $recommended_max"
    echo "  pm.start_servers = $recommended_start"
    echo "  pm.min_spare_servers = $recommended_min"
    echo "  pm.max_spare_servers = $recommended_spare"
    echo ""
}

configure_php_fpm_interactive() {
    local pool_conf="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
    
    if [[ ! -f "$pool_conf" ]]; then
        msg_error "PHP-FPM pool config not found"
        return 1
    fi
    
    local total_ram=$(get_total_ram_mb)
    local available_ram=$((total_ram * 70 / 100))
    local recommended_max=$((available_ram / 80))
    
    # Process Manager Type
    local pm_type
    pm_type=$(whiptail --title "PHP-FPM Process Manager" --menu "Select process manager type:" 14 60 4 \
        "dynamic" "Adjust workers based on load (recommended)" \
        "static" "Fixed number of workers" \
        "ondemand" "Spawn workers on demand (low traffic)" \
        3>&1 1>&2 2>&3)
    
    [[ -z "$pm_type" ]] && return
    
    # Max Children
    local max_children
    max_children=$(whiptail --title "PHP-FPM Max Children" --inputbox \
        "Maximum number of child processes.\n\nYour RAM: ${total_ram}MB\nRecommended: ${recommended_max}\n\nEnter value:" \
        14 60 "$recommended_max" 3>&1 1>&2 2>&3)
    
    [[ -z "$max_children" ]] && return
    
    if [[ "$pm_type" == "dynamic" ]]; then
        local start_servers=$((max_children / 4))
        local min_spare=$((max_children / 8))
        local max_spare=$((max_children / 2))
        
        start_servers=$(whiptail --title "Start Servers" --inputbox \
            "Number of children created on startup:\n(Recommended: $start_servers)" \
            12 60 "$start_servers" 3>&1 1>&2 2>&3)
        
        min_spare=$(whiptail --title "Min Spare Servers" --inputbox \
            "Minimum idle children:\n(Recommended: $min_spare)" \
            12 60 "$min_spare" 3>&1 1>&2 2>&3)
        
        max_spare=$(whiptail --title "Max Spare Servers" --inputbox \
            "Maximum idle children:\n(Recommended: $max_spare)" \
            12 60 "$max_spare" 3>&1 1>&2 2>&3)
        
        # Apply configuration
        sed -i "s/^pm = .*/pm = $pm_type/" "$pool_conf"
        sed -i "s/^pm\.max_children = .*/pm.max_children = $max_children/" "$pool_conf"
        sed -i "s/^pm\.start_servers = .*/pm.start_servers = $start_servers/" "$pool_conf"
        sed -i "s/^pm\.min_spare_servers = .*/pm.min_spare_servers = $min_spare/" "$pool_conf"
        sed -i "s/^pm\.max_spare_servers = .*/pm.max_spare_servers = $max_spare/" "$pool_conf"
    else
        sed -i "s/^pm = .*/pm = $pm_type/" "$pool_conf"
        sed -i "s/^pm\.max_children = .*/pm.max_children = $max_children/" "$pool_conf"
    fi
    
    # Restart PHP-FPM
    systemctl restart php${PHP_VERSION}-fpm
    
    msg_success "PHP-FPM configuration updated and service restarted"
}

configure_php_ini() {
    local php_ini="/etc/php/${PHP_VERSION}/fpm/php.ini"
    
    if [[ ! -f "$php_ini" ]]; then
        msg_error "PHP ini file not found: $php_ini"
        return 1
    fi
    
    local memory_limit
    memory_limit=$(whiptail --title "PHP Memory Limit" --inputbox \
        "Maximum memory per script (e.g., 256M, 512M, 1G):" \
        10 60 "256M" 3>&1 1>&2 2>&3)
    
    [[ -z "$memory_limit" ]] && return
    
    local upload_max
    upload_max=$(whiptail --title "Upload Max Filesize" --inputbox \
        "Maximum upload file size (e.g., 64M, 128M, 256M):" \
        10 60 "64M" 3>&1 1>&2 2>&3)
    
    [[ -z "$upload_max" ]] && return
    
    local post_max
    post_max=$(whiptail --title "Post Max Size" --inputbox \
        "Maximum POST data size (should be >= upload_max_filesize):" \
        10 60 "64M" 3>&1 1>&2 2>&3)
    
    [[ -z "$post_max" ]] && return
    
    local max_exec_time
    max_exec_time=$(whiptail --title "Max Execution Time" --inputbox \
        "Maximum script execution time in seconds:" \
        10 60 "300" 3>&1 1>&2 2>&3)
    
    [[ -z "$max_exec_time" ]] && return
    
    # Apply settings
    sed -i "s/^memory_limit = .*/memory_limit = $memory_limit/" "$php_ini"
    sed -i "s/^upload_max_filesize = .*/upload_max_filesize = $upload_max/" "$php_ini"
    sed -i "s/^post_max_size = .*/post_max_size = $post_max/" "$php_ini"
    sed -i "s/^max_execution_time = .*/max_execution_time = $max_exec_time/" "$php_ini"
    
    systemctl restart php${PHP_VERSION}-fpm
    
    msg_success "PHP configuration updated"
}

# MariaDB Configuration
configure_mariadb() {
    local my_cnf="/etc/mysql/mariadb.conf.d/50-server.cnf"
    
    if [[ ! -f "$my_cnf" ]]; then
        my_cnf="/etc/mysql/my.cnf"
    fi
    
    local total_ram=$(get_total_ram_mb)
    
    msg_info "System RAM: ${total_ram}MB"
    
    echo ""
    echo -e "${CYAN}Current MariaDB Configuration:${NC}"
    mariadb -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';" 2>/dev/null || echo "  (MariaDB not accessible)"
    mariadb -e "SHOW VARIABLES LIKE 'max_connections';" 2>/dev/null || echo ""
    echo ""
}

configure_mariadb_interactive() {
    local total_ram=$(get_total_ram_mb)
    local recommended_buffer=$((total_ram * 50 / 100))  # 50% of RAM for InnoDB buffer
    
    # InnoDB Buffer Pool Size
    local buffer_pool
    buffer_pool=$(whiptail --title "InnoDB Buffer Pool Size" --inputbox \
        "Size of InnoDB buffer pool in MB.\n\nYour RAM: ${total_ram}MB\nRecommended: ${recommended_buffer}M (50% of RAM)\n\nEnter value (e.g., 512M, 1G, 2G):" \
        14 60 "${recommended_buffer}M" 3>&1 1>&2 2>&3)
    
    [[ -z "$buffer_pool" ]] && return
    
    # Max Connections
    local max_conn
    max_conn=$(whiptail --title "Max Connections" --inputbox \
        "Maximum simultaneous connections:\n(Recommended: 100-300 for most sites)" \
        12 60 "151" 3>&1 1>&2 2>&3)
    
    [[ -z "$max_conn" ]] && return
    
    # Query Cache Size
    local query_cache
    query_cache=$(whiptail --title "Query Cache Size" --inputbox \
        "Query cache size (0 to disable, 64M-256M typical):" \
        12 60 "64M" 3>&1 1>&2 2>&3)
    
    [[ -z "$query_cache" ]] && return
    
    # Thread Cache Size
    local thread_cache
    thread_cache=$(whiptail --title "Thread Cache Size" --inputbox \
        "Thread cache size:\n(Recommended: 8-64)" \
        12 60 "16" 3>&1 1>&2 2>&3)
    
    [[ -z "$thread_cache" ]] && return
    
    # Create/Update custom config
    local custom_conf="/etc/mysql/mariadb.conf.d/99-lnmp-tuning.cnf"
    
    cat > "$custom_conf" << EOF
# LNMP Manager - MariaDB Tuning
# Generated: $(date)

[mysqld]
# InnoDB Settings
innodb_buffer_pool_size = $buffer_pool
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT

# Connection Settings
max_connections = $max_conn
thread_cache_size = $thread_cache

# Query Cache
query_cache_type = 1
query_cache_size = $query_cache
query_cache_limit = 2M

# Temp Tables
tmp_table_size = 64M
max_heap_table_size = 64M

# Buffer Sizes
key_buffer_size = 32M
read_buffer_size = 2M
read_rnd_buffer_size = 4M
sort_buffer_size = 4M
join_buffer_size = 4M
EOF
    
    systemctl restart mariadb
    
    msg_success "MariaDB configuration updated at $custom_conf"
}

# Security Hardening
harden_php() {
    local php_ini="/etc/php/${PHP_VERSION}/fpm/php.ini"
    
    msg_info "Applying PHP security hardening (safe mode)..."
    
    # ═══════════════════════════════════════════════════════════════════════
    # PHP HARDENING - PENJELASAN / EXPLANATION
    # ═══════════════════════════════════════════════════════════════════════
    # 
    # 1. disable_functions - Menonaktifkan fungsi berbahaya
    #    - passthru, shell_exec, system, proc_open: eksekusi shell command
    #    - popen, proc_get_status, proc_nice, proc_terminate: kontrol proses
    #    - show_source, highlight_file: expose source code
    #    - TIDAK dinonaktifkan: exec (dibutuhkan beberapa plugin WordPress)
    #    - TIDAK dinonaktifkan: curl_* (dibutuhkan untuk API calls)
    #
    # 2. expose_php = Off - Sembunyikan versi PHP dari header HTTP
    #    - Mencegah attacker mengetahui versi PHP untuk exploit
    #
    # 3. allow_url_fopen = On - TETAP AKTIF!
    #    - Dibutuhkan WordPress untuk update, plugin, themes
    #    - Dibutuhkan Laravel untuk HTTP client
    #
    # 4. allow_url_include = Off - Nonaktifkan include file remote
    #    - Mencegah Remote File Inclusion (RFI) attack
    #    - Tidak mempengaruhi fungsi normal website
    #
    # 5. session.cookie_httponly = 1 - Cookie tidak bisa diakses JavaScript
    #    - Mencegah XSS stealing session cookies
    #
    # 6. session.cookie_secure = 0 - TETAP OFF untuk kompatibilitas
    #    - Jika aktif, cookie hanya dikirim via HTTPS
    #    - Bisa break website yang belum pakai HTTPS
    #
    # 7. session.use_strict_mode = 1 - Reject uninitialized session IDs
    #    - Mencegah session fixation attack
    #
    # 8. display_errors = Off - Jangan tampilkan error ke browser
    #    - Error bisa expose path dan informasi sensitif
    #
    # 9. log_errors = On - Simpan error ke log file
    #    - Untuk debugging tanpa expose ke user
    #
    # 10. open_basedir - Batasi akses file PHP
    #     - PHP hanya bisa akses direktori tertentu
    # ═══════════════════════════════════════════════════════════════════════

    # Backup original
    cp "$php_ini" "${php_ini}.backup.$(date +%Y%m%d%H%M%S)"
    
    # Disable dangerous functions (safe list - won't break WordPress/Laravel)
    sed -i "s/^disable_functions = .*/disable_functions = passthru,shell_exec,system,proc_open,popen,proc_get_status,proc_nice,proc_terminate,show_source,highlight_file/" "$php_ini"
    
    # Hide PHP version (tidak mempengaruhi fungsi apapun)
    sed -i "s/^expose_php = .*/expose_php = Off/" "$php_ini"
    
    # KEEP allow_url_fopen ON - needed for WordPress updates, plugins, API calls
    sed -i "s/^allow_url_fopen = .*/allow_url_fopen = On/" "$php_ini"
    
    # Disable remote file include (ini yang berbahaya, bukan url_fopen)
    sed -i "s/^allow_url_include = .*/allow_url_include = Off/" "$php_ini"
    
    # Session security (safe settings)
    sed -i "s/^session.cookie_httponly = .*/session.cookie_httponly = 1/" "$php_ini"
    # Keep cookie_secure off for HTTP compatibility
    sed -i "s/^session.cookie_secure = .*/session.cookie_secure = 0/" "$php_ini"
    sed -i "s/^session.use_strict_mode = .*/session.use_strict_mode = 1/" "$php_ini"
    
    # Error handling (production mode)
    sed -i "s/^display_errors = .*/display_errors = Off/" "$php_ini"
    sed -i "s/^log_errors = .*/log_errors = On/" "$php_ini"
    
    systemctl restart php${PHP_VERSION}-fpm
    
    msg_success "PHP security hardening applied (safe mode)"
    echo ""
    echo -e "${CYAN}Perubahan yang diterapkan:${NC}"
    echo "  • disable_functions: passthru, shell_exec, system, proc_*, show_source"
    echo "  • expose_php: Off (sembunyikan versi PHP)"
    echo "  • allow_url_include: Off (cegah RFI attack)"
    echo "  • session.cookie_httponly: On (cegah XSS)"
    echo "  • display_errors: Off (sembunyikan error)"
    echo ""
    echo -e "${GREEN}Yang TIDAK diubah (untuk kompatibilitas):${NC}"
    echo "  • allow_url_fopen: On (WordPress/Laravel butuh ini)"
    echo "  • exec: tidak dinonaktifkan (beberapa plugin butuh)"
    echo ""
}

harden_mariadb() {
    msg_info "Applying MariaDB security hardening (safe mode)..."
    
    # ═══════════════════════════════════════════════════════════════════════
    # MARIADB HARDENING - PENJELASAN / EXPLANATION
    # ═══════════════════════════════════════════════════════════════════════
    #
    # 1. local_infile = 0 - Nonaktifkan LOAD DATA LOCAL
    #    - Mencegah attacker membaca file lokal via SQL injection
    #    - Tidak mempengaruhi WordPress/Laravel
    #
    # 2. symbolic-links = 0 - Nonaktifkan symbolic links
    #    - Mencegah akses file diluar direktori data MySQL
    #
    # 3. bind-address = 127.0.0.1 - Hanya terima koneksi lokal
    #    - Database tidak bisa diakses dari luar server
    #    - Jika butuh remote access, ubah ke 0.0.0.0
    #
    # 4. secure_file_priv - Batasi direktori untuk file operations
    #    - SELECT INTO OUTFILE hanya bisa ke direktori ini
    #
    # 5. slow_query_log - Log query yang lambat
    #    - Untuk debugging performance
    #    - Default threshold: 2 detik
    # ═══════════════════════════════════════════════════════════════════════
    
    local custom_conf="/etc/mysql/mariadb.conf.d/99-lnmp-security.cnf"
    
    cat > "$custom_conf" << 'EOF'
# LNMP Manager - MariaDB Security Hardening
# Safe defaults - tidak akan merusak aplikasi

[mysqld]
# Disable local file loading (cegah SQL injection file read)
local_infile = 0

# Disable symbolic links (security)
symbolic-links = 0

# Bind to localhost only (ubah ke 0.0.0.0 jika butuh remote)
bind-address = 127.0.0.1

# Secure file permissions
secure_file_priv = /var/lib/mysql-files

# Logging
log_error = /var/log/mysql/error.log
general_log = 0
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
EOF

    mkdir -p /var/lib/mysql-files
    chown mysql:mysql /var/lib/mysql-files
    
    systemctl restart mariadb
    
    msg_success "MariaDB security hardening applied (safe mode)"
    echo ""
    echo -e "${CYAN}Perubahan yang diterapkan:${NC}"
    echo "  • local_infile: Off (cegah file read via SQL injection)"
    echo "  • symbolic-links: Off (cegah akses file ilegal)"
    echo "  • bind-address: 127.0.0.1 (hanya koneksi lokal)"
    echo "  • slow_query_log: On (log query lambat > 2 detik)"
    echo ""
    echo -e "${YELLOW}Catatan:${NC}"
    echo "  • Jalankan 'mariadb-secure-installation' untuk keamanan tambahan"
    echo "  • Remote access: edit bind-address di $custom_conf"
    echo ""
}

harden_nginx() {
    msg_info "Applying Nginx security hardening (safe mode)..."
    
    # ═══════════════════════════════════════════════════════════════════════
    # NGINX HARDENING - PENJELASAN / EXPLANATION
    # ═══════════════════════════════════════════════════════════════════════
    #
    # 1. server_tokens off - Sembunyikan versi Nginx
    #    - Mencegah attacker mengetahui versi untuk exploit
    #
    # 2. X-Frame-Options: SAMEORIGIN
    #    - Mencegah clickjacking - website tidak bisa di-embed di iframe
    #    - SAMEORIGIN: hanya bisa embed dari domain yang sama
    #
    # 3. X-Content-Type-Options: nosniff
    #    - Mencegah MIME type sniffing
    #    - Browser harus pakai Content-Type yang diberikan server
    #
    # 4. X-XSS-Protection: 1; mode=block
    #    - Aktifkan XSS filter browser
    #    - Block halaman jika detect XSS attack
    #
    # 5. Referrer-Policy: strict-origin-when-cross-origin
    #    - Kontrol informasi referrer yang dikirim
    #    - Same-origin: kirim full URL
    #    - Cross-origin: hanya kirim origin (domain)
    #
    # 6. SSL Configuration
    #    - TLSv1.2 dan TLSv1.3 saja (nonaktifkan SSLv3, TLSv1, TLSv1.1)
    #    - Cipher suite yang aman
    #
    # 7. Rate Limiting Zones (template)
    #    - Bisa dipakai untuk limit request per IP
    #    - Tidak langsung aktif, perlu ditambahkan ke server block
    # ═══════════════════════════════════════════════════════════════════════
    
    local nginx_conf="/etc/nginx/nginx.conf"
    local security_conf="/etc/nginx/conf.d/security.conf"
    
    # Create security configuration
    cat > "$security_conf" << 'EOF'
# LNMP Manager - Nginx Security Hardening
# Safe defaults - tidak akan merusak website

# Hide Nginx version (sembunyikan versi)
server_tokens off;

# Security Headers
# X-Frame-Options: cegah clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# X-Content-Type-Options: cegah MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# X-XSS-Protection: aktifkan XSS filter browser
add_header X-XSS-Protection "1; mode=block" always;

# Referrer-Policy: kontrol info referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# SSL Configuration (aktif saat HTTPS digunakan)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# Rate Limiting Zone (template - tambahkan limit_req di server block untuk aktifkan)
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;
EOF
    
    nginx -t && systemctl reload nginx
    
    msg_success "Nginx security hardening applied (safe mode)"
    echo ""
    echo -e "${CYAN}Perubahan yang diterapkan:${NC}"
    echo "  • server_tokens: Off (sembunyikan versi Nginx)"
    echo "  • X-Frame-Options: SAMEORIGIN (cegah clickjacking)"
    echo "  • X-Content-Type-Options: nosniff (cegah MIME sniffing)"
    echo "  • X-XSS-Protection: On (aktifkan XSS filter)"
    echo "  • SSL: TLSv1.2/1.3 only (nonaktifkan protokol lama)"
    echo ""
}

harden_all() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}           SECURITY HARDENING - SAFE MODE                      ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    msg_info "Menerapkan hardening ke semua service..."
    echo ""
    
    harden_php
    harden_mariadb
    harden_nginx
    
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           HARDENING COMPLETE - SEMUA AMAN!                    ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Catatan Penting:${NC}"
    echo "  • Semua setting sudah aman dan tidak merusak fungsi website"
    echo "  • WordPress, Laravel, dan CMS lain tetap berfungsi normal"
    echo "  • Backup config otomatis dibuat sebelum perubahan"
    echo ""
}

# Nginx Compression Configuration
configure_nginx_compression() {
    msg_info "Configuring Nginx compression (gzip + brotli)..."
    
    # ═══════════════════════════════════════════════════════════════════════
    # NGINX COMPRESSION - PENJELASAN / EXPLANATION
    # ═══════════════════════════════════════════════════════════════════════
    #
    # GZIP Compression:
    # - Kompresi standar yang didukung semua browser
    # - Mengurangi ukuran file text (HTML, CSS, JS) hingga 70-90%
    # - gzip_comp_level: 1-9 (4-6 optimal untuk balance CPU/compression)
    # - gzip_min_length: minimal ukuran file untuk dikompresi
    #
    # Brotli Compression:
    # - Kompresi modern, 15-25% lebih baik dari gzip
    # - Didukung browser modern (Chrome, Firefox, Edge, Safari)
    # - Fallback ke gzip untuk browser lama
    # - brotli_comp_level: 1-11 (4-6 untuk dynamic, 11 untuk static)
    #
    # File Types yang Dikompresi:
    # - text/html, text/css, text/javascript
    # - application/json, application/javascript
    # - image/svg+xml, font/woff, font/woff2
    # ═══════════════════════════════════════════════════════════════════════
    
    local compression_conf="/etc/nginx/conf.d/compression.conf"
    
    # Check if brotli module is available
    local has_brotli=false
    if nginx -V 2>&1 | grep -q "brotli"; then
        has_brotli=true
        msg_info "Brotli module detected"
    else
        msg_warning "Brotli module not detected - only gzip will be configured"
    fi
    
    cat > "$compression_conf" << 'EOF'
# LNMP Manager - Nginx Compression Configuration
# Gzip + Brotli untuk performa optimal

# ============================================================================
# GZIP Compression
# ============================================================================
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 5;
gzip_min_length 256;
gzip_buffers 16 8k;
gzip_http_version 1.1;

# Tipe file yang akan dikompresi gzip
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/x-javascript
    application/xml
    application/xml+rss
    application/atom+xml
    application/rss+xml
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-font-opentype
    application/x-font-truetype
    font/eot
    font/opentype
    font/otf
    font/ttf
    image/svg+xml
    image/vnd.microsoft.icon
    image/x-icon;

# Disable gzip untuk IE6
gzip_disable "MSIE [1-6]\.";
EOF

    # Add brotli config if module is available
    if [[ "$has_brotli" == true ]]; then
        cat >> "$compression_conf" << 'EOF'

# ============================================================================
# Brotli Compression (lebih efisien dari gzip)
# ============================================================================
brotli on;
brotli_comp_level 6;
brotli_min_length 256;
brotli_static on;

# Tipe file yang akan dikompresi brotli
brotli_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/x-javascript
    application/xml
    application/xml+rss
    application/atom+xml
    application/rss+xml
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-font-opentype
    application/x-font-truetype
    font/eot
    font/opentype
    font/otf
    font/ttf
    image/svg+xml
    image/vnd.microsoft.icon
    image/x-icon;
EOF
    fi

    nginx -t && systemctl reload nginx
    
    msg_success "Nginx compression configured"
    echo ""
    echo -e "${CYAN}Konfigurasi Compression:${NC}"
    echo "  • Gzip: Level 5, min 256 bytes"
    if [[ "$has_brotli" == true ]]; then
        echo "  • Brotli: Level 6, min 256 bytes"
        echo "  • Static Brotli: On (untuk file .br yang sudah pre-compressed)"
    else
        echo "  • Brotli: Tidak tersedia (module tidak terinstall)"
        echo ""
        echo -e "${YELLOW}Untuk mengaktifkan Brotli:${NC}"
        echo "  • Nginx perlu dikompile dengan ngx_brotli module"
        echo "  • Atau gunakan Nginx dari Cloudflare/custom build"
    fi
    echo ""
    echo -e "${GREEN}File types yang dikompresi:${NC}"
    echo "  • HTML, CSS, JavaScript, JSON, XML"
    echo "  • SVG, Font files (TTF, OTF, WOFF)"
    echo ""
    echo -e "${YELLOW}Lokasi config: ${compression_conf}${NC}"
    echo ""
}

configure_nginx_compression_interactive() {
    local comp_level
    
    comp_level=$(whiptail --title "Gzip Compression Level" --menu \
        "Pilih level kompresi gzip:\n\n1-3: Cepat, kompresi rendah\n4-6: Balance (recommended)\n7-9: Lambat, kompresi tinggi" \
        18 60 6 \
        "3" "Fast (CPU rendah)" \
        "4" "Balanced-Fast" \
        "5" "Balanced (default)" \
        "6" "Balanced-High" \
        "7" "High Compression" \
        "9" "Maximum (CPU tinggi)" \
        3>&1 1>&2 2>&3)
    
    [[ -z "$comp_level" ]] && return
    
    configure_nginx_compression
}

menu_install() {
    local choice
    choice=$(whiptail --title "Install Components" --menu "Choose component to install:" 22 60 12 \
        "1" "Install All (Full LNMP Stack)" \
        "2" "Install PHP ${PHP_VERSION}" \
        "3" "Install Nginx" \
        "4" "Install MariaDB ${MARIADB_VERSION}" \
        "5" "Install Redis" \
        "6" "Install Certbot" \
        "7" "Install UFW Firewall" \
        "8" "Install Fail2ban" \
        "9" "Create Swap Memory" \
        "10" "Back to Main Menu" \
        3>&1 1>&2 2>&3)
    
    case $choice in
        1) install_all; press_enter ;;
        2) install_php; press_enter ;;
        3) install_nginx; press_enter ;;
        4) install_mariadb_interactive; press_enter ;;
        5) install_redis; press_enter ;;
        6) install_certbot; press_enter ;;
        7) install_ufw; press_enter ;;
        8) install_fail2ban; press_enter ;;
        9) create_swap 2; press_enter ;;
        10) return ;;
    esac
}

menu_site_create() {
    local site_type
    site_type=$(whiptail --title "Create Site" --menu "Choose site type:" 12 50 3 \
        "1" "PHP Site (with document root)" \
        "2" "Reverse Proxy (backend IP:port)" \
        "3" "Cancel" \
        3>&1 1>&2 2>&3)
    
    case $site_type in
        1)
            local domain
            domain=$(whiptail --title "PHP Site" --inputbox "Enter domain name:" 10 50 3>&1 1>&2 2>&3)
            if [[ -n "$domain" ]]; then
                if whiptail --title "SSL" --yesno "Enable SSL with Certbot?" 8 40; then
                    create_php_site "$domain" "true"
                else
                    create_php_site "$domain" "false"
                fi
                press_enter
            fi
            ;;
        2)
            local domain
            domain=$(whiptail --title "Reverse Proxy" --inputbox "Enter domain name:" 10 50 3>&1 1>&2 2>&3)
            if [[ -n "$domain" ]]; then
                local backend
                backend=$(whiptail --title "Backend" --inputbox "Enter backend address (IP:port):\nExample: 127.0.0.1:3000" 12 50 3>&1 1>&2 2>&3)
                if [[ -n "$backend" ]]; then
                    if whiptail --title "SSL" --yesno "Enable SSL with Certbot?" 8 40; then
                        create_proxy_site "$domain" "$backend" "true"
                    else
                        create_proxy_site "$domain" "$backend" "false"
                    fi
                    press_enter
                fi
            fi
            ;;
        3) return ;;
    esac
}

menu_site() {
    while true; do
        local choice
        choice=$(whiptail --title "Site Management" --menu "Choose option:" 20 60 10 \
            "1" "Create New Site" \
            "2" "Delete Site" \
            "3" "Enable Site" \
            "4" "Disable Site" \
            "5" "Configure SSL" \
            "6" "Create Database for Site" \
            "7" "Create Health Endpoint" \
            "8" "List All Sites" \
            "9" "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) menu_site_create ;;
            2)
                local domain
                domain=$(whiptail --title "Delete Site" --inputbox "Enter domain to delete:" 10 50 3>&1 1>&2 2>&3)
                if [[ -n "$domain" ]]; then
                    if whiptail --title "Confirm" --yesno "Are you sure you want to delete '${domain}'?" 8 50; then
                        delete_site "$domain"
                        press_enter
                    fi
                fi
                ;;
            3)
                local domain
                domain=$(whiptail --title "Enable Site" --inputbox "Enter domain to enable:" 10 50 3>&1 1>&2 2>&3)
                if [[ -n "$domain" ]]; then
                    enable_site "$domain"
                    press_enter
                fi
                ;;
            4)
                local domain
                domain=$(whiptail --title "Disable Site" --inputbox "Enter domain to disable:" 10 50 3>&1 1>&2 2>&3)
                if [[ -n "$domain" ]]; then
                    disable_site "$domain"
                    press_enter
                fi
                ;;
            5)
                local domain
                domain=$(whiptail --title "SSL" --inputbox "Enter domain for SSL:" 10 50 3>&1 1>&2 2>&3)
                if [[ -n "$domain" ]]; then
                    local email
                    email=$(whiptail --title "SSL" --inputbox "Enter email for SSL (optional):" 10 50 3>&1 1>&2 2>&3)
                    setup_ssl "$domain" "$email"
                    press_enter
                fi
                ;;
            6)
                create_database_interactive
                press_enter
                ;;
            7)
                local domain
                domain=$(whiptail --title "Health Check" --inputbox "Enter domain:" 10 50 3>&1 1>&2 2>&3)
                if [[ -n "$domain" ]]; then
                    create_health_endpoint "$domain"
                    press_enter
                fi
                ;;
            8)
                list_sites
                press_enter
                ;;
            9) return ;;
            *) return ;;
        esac
    done
}

menu_service() {
    while true; do
        local choice
        choice=$(whiptail --title "Service Management" --menu "Choose service:" 18 50 9 \
            "1" "Restart Nginx" \
            "2" "Restart PHP-FPM" \
            "3" "Restart MariaDB" \
            "4" "Restart Redis" \
            "5" "Stop Nginx" \
            "6" "Stop PHP-FPM" \
            "7" "Stop MariaDB" \
            "8" "Stop Redis" \
            "9" "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) service_action nginx restart; press_enter ;;
            2) service_action php-fpm restart; press_enter ;;
            3) service_action mariadb restart; press_enter ;;
            4) service_action redis restart; press_enter ;;
            5) service_action nginx stop; press_enter ;;
            6) service_action php-fpm stop; press_enter ;;
            7) service_action mariadb stop; press_enter ;;
            8) service_action redis stop; press_enter ;;
            9) return ;;
            *) return ;;
        esac
    done
}

menu_config() {
    while true; do
        local choice
        choice=$(whiptail --title "Configuration & Tuning" --menu "Choose option:" 24 65 15 \
            "1" "Configure PHP-FPM (processes/RAM)" \
            "2" "Configure PHP Settings (memory/upload)" \
            "3" "Configure MariaDB (buffer/connections)" \
            "4" "Configure Nginx Compression (gzip/brotli)" \
            "5" "Configure OPcache (PHP accelerator)" \
            "6" "Configure Nginx Workers" \
            "7" "View Current PHP-FPM Config" \
            "8" "View Current MariaDB Config" \
            "9" "Check SSL Auto-Renewal" \
            "10" "Harden PHP (security)" \
            "11" "Harden MariaDB (security)" \
            "12" "Harden Nginx (security)" \
            "13" "Harden All (full security)" \
            "14" "Back to Main Menu" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) configure_php_fpm_interactive; press_enter ;;
            2) configure_php_ini; press_enter ;;
            3) configure_mariadb_interactive; press_enter ;;
            4) configure_nginx_compression; press_enter ;;
            5) configure_opcache; press_enter ;;
            6) configure_nginx_workers; press_enter ;;
            7) configure_php_fpm; press_enter ;;
            8) configure_mariadb; press_enter ;;
            9) check_ssl_renewal; press_enter ;;
            10) harden_php; press_enter ;;
            11) harden_mariadb; press_enter ;;
            12) harden_nginx; press_enter ;;
            13) harden_all; press_enter ;;
            14) return ;;
            *) return ;;
        esac
    done
}

menu_main() {
    check_whiptail
    
    while true; do
        print_banner
        
        local choice
        choice=$(whiptail --title "LNMP Stack Manager" --menu "Choose an option:" 18 60 7 \
            "1" "Install LNMP Stack" \
            "2" "Site Management" \
            "3" "Service Management" \
            "4" "Configuration & Tuning" \
            "5" "View Status" \
            "6" "Exit" \
            3>&1 1>&2 2>&3)
        
        case $choice in
            1) menu_install ;;
            2) menu_site ;;
            3) menu_service ;;
            4) menu_config ;;
            5) show_status; press_enter ;;
            6) exit 0 ;;
            *) exit 0 ;;
        esac
    done
}

# ============================================================================
# CLI INTERFACE
# ============================================================================

show_help() {
    echo "LNMP Stack Manager for Debian"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  (no args)              Launch interactive menu"
    echo ""
    echo "  install                Install full LNMP stack"
    echo "  install php            Install PHP ${PHP_VERSION}"
    echo "  install nginx          Install Nginx"
    echo "  install mariadb [--password <pass>]"
    echo "                         Install MariaDB (optional: set root password)"
    echo "  install redis          Install Redis server"
    echo "  install certbot        Install Certbot"
    echo ""
    echo "  site create php <domain> [--ssl]"
    echo "                         Create PHP site"
    echo "  site create proxy <domain> <ip:port> [--ssl]"
    echo "                         Create reverse proxy site"
    echo "  site delete <domain>   Delete site"
    echo "  site enable <domain>   Enable site"
    echo "  site disable <domain>  Disable site"
    echo "  site ssl <domain> [--email <email>]"
    echo "                         Setup SSL for site"
    echo "  site list              List all sites"
    echo ""
    echo "  service restart <nginx|php|mariadb|redis>"
    echo "  service stop <nginx|php|mariadb|redis>"
    echo "  service start <nginx|php|mariadb|redis>"
    echo ""
    echo "  config php-fpm         Configure PHP-FPM (interactive)"
    echo "  config php             Configure PHP settings (interactive)"
    echo "  config mariadb         Configure MariaDB (interactive)"
    echo "  config show            Show current configurations"
    echo ""
    echo "  harden php             Apply PHP security hardening"
    echo "  harden mariadb         Apply MariaDB security hardening"
    echo "  harden nginx           Apply Nginx security hardening"
    echo "  harden all             Apply all security hardening"
    echo ""
    echo "  status                 Show service status"
    echo "  help                   Show this help"
    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

main() {
    check_root
    check_debian
    
    # No arguments - launch interactive menu
    if [[ $# -eq 0 ]]; then
        menu_main
        exit 0
    fi
    
    # CLI mode
    case $1 in
        install)
            case $2 in
                "") install_all ;;
                php) install_php ;;
                nginx) install_nginx ;;
                mariadb)
                    # Check for --password flag
                    if [[ "$3" == "--password" && -n "$4" ]]; then
                        install_mariadb "$4"
                    else
                        install_mariadb
                    fi
                    ;;
                redis) install_redis ;;
                certbot) install_certbot ;;
                *) msg_error "Unknown component: $2"; show_help ;;
            esac
            ;;
        site)
            case $2 in
                create)
                    case $3 in
                        php)
                            local ssl_flag=""
                            [[ "$5" == "--ssl" ]] && ssl_flag="true"
                            create_php_site "$4" "$ssl_flag"
                            ;;
                        proxy)
                            local ssl_flag=""
                            [[ "$6" == "--ssl" ]] && ssl_flag="true"
                            create_proxy_site "$4" "$5" "$ssl_flag"
                            ;;
                        *)
                            msg_error "Site type required: php or proxy"
                            show_help
                            ;;
                    esac
                    ;;
                delete) delete_site "$3" ;;
                enable) enable_site "$3" ;;
                disable) disable_site "$3" ;;
                ssl)
                    local email=""
                    if [[ "$4" == "--email" ]]; then
                        email="$5"
                    fi
                    setup_ssl "$3" "$email"
                    ;;
                list) list_sites ;;
                *) msg_error "Unknown site command: $2"; show_help ;;
            esac
            ;;
        service)
            case $3 in
                nginx|php|php-fpm|mariadb|mysql)
                    service_action "$3" "$2"
                    ;;
                *)
                    msg_error "Unknown service: $3"
                    show_help
                    ;;
            esac
            ;;
        config)
            case $2 in
                php-fpm) configure_php_fpm_interactive ;;
                php) configure_php_ini ;;
                mariadb) configure_mariadb_interactive ;;
                show)
                    configure_php_fpm
                    configure_mariadb
                    ;;
                *) msg_error "Unknown config: $2"; show_help ;;
            esac
            ;;
        harden)
            case $2 in
                php) harden_php ;;
                mariadb) harden_mariadb ;;
                nginx) harden_nginx ;;
                all) harden_all ;;
                *) msg_error "Unknown harden target: $2"; show_help ;;
            esac
            ;;
        status) show_status ;;
        help|--help|-h) show_help ;;
        *)
            msg_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
