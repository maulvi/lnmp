# LNMP Stack Manager

Script otomatis untuk instalasi dan manajemen LNMP (Linux, Nginx, MariaDB, PHP) stack pada Debian.

## Fitur

### 🚀 Instalasi
- **PHP 8.5** dengan ekstensi lengkap (mysqli, pdo, curl, gd, mbstring, redis, dll)
- **Nginx 1.28.0** (custom build dengan Brotli support)
- **MariaDB 11.8** dengan opsi password saat install
- **Redis** dari repository resmi
- **Certbot** untuk SSL/HTTPS
- **UFW Firewall** dengan auto-detect SSH port
- **Fail2ban** untuk brute force protection

### 🌐 Site Management
- Create PHP sites dengan document root
- Create Reverse Proxy sites
- Enable/Disable sites
- SSL certificate dengan Let's Encrypt
- Health check endpoint (`/health.php`)
- Database creation per-site

### ⚙️ Configuration & Tuning
- PHP-FPM tuning (auto-calculate berdasarkan RAM)
- OPcache optimization
- MariaDB buffer/connections tuning
- Nginx workers tuning
- Gzip + Brotli compression
- Log rotation

### 🔒 Security Hardening
- PHP hardening (disable dangerous functions, hide version)
- MariaDB hardening (local only, disable file loading)
- Nginx hardening (security headers, TLS 1.2/1.3)
- UFW firewall (auto-detect SSH port)
- Fail2ban (SSH + Nginx protection)

### 📊 Monitoring & Logging
- Service status dengan SSL expiry date
- Audit log (`/var/log/lnmp-manager.log`)
- Health check endpoints
- SSL auto-renewal check

## Quick Start

```bash
# Download script
wget https://your-repo/lnmp.sh
chmod +x lnmp.sh

# Run interactive mode
sudo ./lnmp.sh

# Or install everything at once
sudo ./lnmp.sh install
```

## Usage

### Interactive Mode
```bash
sudo ./lnmp.sh
```
Akan menampilkan menu interaktif dengan semua opsi.

### CLI Mode

#### Installation
```bash
# Install full stack (includes UFW, fail2ban, optimizations)
sudo ./lnmp.sh install

# Install individual components
sudo ./lnmp.sh install php
sudo ./lnmp.sh install nginx
sudo ./lnmp.sh install mariadb --password YourSecurePassword
sudo ./lnmp.sh install redis
sudo ./lnmp.sh install certbot
```

#### Site Management
```bash
# Create PHP site
sudo ./lnmp.sh site create php example.com
sudo ./lnmp.sh site create php example.com --ssl

# Create reverse proxy
sudo ./lnmp.sh site create proxy api.example.com 127.0.0.1:3000
sudo ./lnmp.sh site create proxy api.example.com 127.0.0.1:3000 --ssl

# Manage sites
sudo ./lnmp.sh site list
sudo ./lnmp.sh site enable example.com
sudo ./lnmp.sh site disable example.com
sudo ./lnmp.sh site delete example.com

# SSL
sudo ./lnmp.sh site ssl example.com --email admin@example.com
```

#### Service Management
```bash
sudo ./lnmp.sh service restart nginx
sudo ./lnmp.sh service restart php
sudo ./lnmp.sh service restart mariadb
sudo ./lnmp.sh service restart redis

sudo ./lnmp.sh status
```

#### Configuration
```bash
# Interactive configuration
sudo ./lnmp.sh config php-fpm
sudo ./lnmp.sh config php
sudo ./lnmp.sh config mariadb
sudo ./lnmp.sh config show
```

#### Security Hardening
```bash
sudo ./lnmp.sh harden php
sudo ./lnmp.sh harden mariadb
sudo ./lnmp.sh harden nginx
sudo ./lnmp.sh harden all
```

## Configuration Files

| Service | Config Location |
|---------|----------------|
| PHP-FPM Pool | `/etc/php/8.5/fpm/pool.d/www.conf` |
| PHP Settings | `/etc/php/8.5/fpm/php.ini` |
| OPcache | `/etc/php/8.5/fpm/conf.d/10-opcache.ini` |
| MariaDB | `/etc/mysql/mariadb.conf.d/99-lnmp-*.cnf` |
| Nginx Sites | `/etc/nginx/sites-available/` |
| Nginx Security | `/etc/nginx/conf.d/security.conf` |
| Nginx Compression | `/etc/nginx/conf.d/compression.conf` |
| Fail2ban | `/etc/fail2ban/jail.local` |
| Log Rotation | `/etc/logrotate.d/lnmp` |

## Logs

| Log | Location |
|-----|----------|
| LNMP Manager | `/var/log/lnmp-manager.log` |
| Nginx Access | `/var/log/nginx/access.log` |
| Nginx Error | `/var/log/nginx/error.log` |
| PHP-FPM | `/var/log/php8.5-fpm.log` |
| MariaDB | `/var/log/mysql/error.log` |
| MariaDB Slow Query | `/var/log/mysql/slow.log` |

## Backups

Config backups are stored in `/var/backups/lnmp/` with timestamp.

## Health Check

After creating a site, you can create a health endpoint:
```bash
sudo ./lnmp.sh
# Site Management → Create Health Endpoint
```

Access via: `https://yoursite.com/health.php`

Response:
```json
{
  "status": "ok",
  "timestamp": "2024-12-08T00:00:00+07:00",
  "checks": {
    "php": "ok",
    "mariadb": "ok",
    "redis": "ok"
  }
}
```

## Security Notes

### UFW Firewall
- Auto-detects custom SSH port from `/etc/ssh/sshd_config`
- Confirms before enabling to prevent lockout
- Only opens: SSH, HTTP (80), HTTPS (443)

### PHP Hardening (Safe Mode)
- `allow_url_fopen` tetap **ON** (WordPress/Laravel butuh ini)
- `exec` tidak dinonaktifkan (beberapa plugin butuh)
- Functions yang dinonaktifkan: `passthru, shell_exec, system, proc_open`

### MariaDB
- Bind to localhost only (127.0.0.1)
- Remote access disabled by default
- Run `mariadb-secure-installation` for additional security

## Requirements

- Debian 11 (Bullseye) or Debian 12 (Bookworm)
- Root access
- Minimum 1GB RAM (2GB recommended)

## License

MIT License
