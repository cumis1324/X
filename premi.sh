#!/bin/bash

# --- VARIASI WARNA ---
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
# ==================================================
# REPO
REPO="https://raw.githubusercontent.com/xyoruz/X/main/"

# --- FUNGSI PEMBANTU ---
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green}=======================================${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green}=======================================${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green}=======================================${FONT}"
        echo -e "${Green} # $1 berhasil dipasang${FONT}"
        echo -e "${green}=======================================${FONT}"
        sleep 2
    fi
}

function is_root() {
    if [[ 0 -ne "$UID" ]]; then
        print_error "Anda harus menjalankan skrip ini sebagai user root."
        exit 1
    fi
}

function check_virt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        print_error "OpenVZ tidak didukung."
        exit 1
    fi
}

# --- PRA-INSTALASI ---
function initial_check() {
    is_root
    check_virt
    clear

    # // Cek Arsitektur
    if [[ $(uname -m) != "x86_64" ]]; then
        print_error "Arsitektur tidak didukung ($(uname -m))"
        exit 1
    fi
    print_ok "Arsitektur didukung ($(uname -m))"

    # // Cek OS
    # Menggunakan cara yang lebih andal untuk mendapatkan info OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_NAME=$PRETTY_NAME
    else
        print_error "Tidak dapat mendeteksi sistem operasi."
        exit 1
    fi
    
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        print_ok "OS didukung ($OS_NAME)"
    else
        print_error "OS tidak didukung ($OS_NAME)"
        exit 1
    fi

    # // Cek IP
    export IP=$(curl -sS icanhazip.com)
    if [[ -z "$IP" ]]; then
        print_error "IP Address tidak terdeteksi."
        exit 1
    else
        print_ok "IP Address terdeteksi: $IP"
    fi
    
    # // Konfirmasi Instalasi
    echo ""
    read -p "$(echo -e "Tekan ${GRAY}[${NC}${green}Enter${NC}${GRAY}]${NC} untuk memulai instalasi")"
}

# --- INSTALASI UTAMA ---
function first_setup() {
    timedatectl set-timezone Asia/Jakarta
    
    # // Update sistem
    print_install "Memperbarui sistem"
    apt-get update -y
    
    # // Install HAProxy
    # Menggunakan versi dari repo resmi Ubuntu 24.04/Debian 12 yang lebih stabil dan aman
    print_install "Menginstall HAProxy"
    apt-get install -y haproxy
    print_success "HAProxy"
}

function base_package() {
    print_install "Menginstall paket-paket yang dibutuhkan"
    # Menggabungkan instalasi paket agar lebih efisien dan rapi
    apt-get install -y --no-install-recommends \
    software-properties-common debconf-utils lolcat figlet wondershaper \
    zip pwgen openssl netcat socat cron bash-completion \
    speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config \
    libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
    libcurl4-nss-dev flex bison make libnss3-tools libevent-dev \
    bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev \
    sed dirmngr libxml-parser-perl build-essential gcc g++ python3 \
    htop lsof tar wget curl ruby unzip p7zip-full python3-pip \
    libc6 util-linux msmtp-mta ca-certificates bsd-mailx \
    iptables iptables-persistent netfilter-persistent net-tools \
    gnupg gnupg2 lsb-release shc cmake git screen xz-utils \
    apt-transport-https gnupg1 dnsutils ntpdate chrony jq openvpn easy-rsa

    # Hapus paket yang berpotensi konflik
    apt-get remove --purge -y ufw firewalld exim4*
    
    # Konfigurasi Chrony untuk sinkronisasi waktu
    systemctl enable --now chrony
    ntpdate pool.ntp.org

    print_success "Paket-paket penting"
}

function make_folder_xray() {
    print_install "Membuat direktori dan file konfigurasi awal"
    mkdir -p /etc/xray /var/log/xray /var/lib/kyt /var/www/html
    mkdir -p /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh
    mkdir -p /etc/bot /etc/user-create
    mkdir -p /etc/kyt/limit/vmess/ip /etc/kyt/limit/vless/ip /etc/kyt/limit/trojan/ip /etc/kyt/limit/ssh/ip

    # Buat file database kosong
    touch /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db

    # Set permission yang benar
    chown www-data:www-data /var/log/xray
    chmod 755 /var/log/xray # 755 lebih umum daripada +x
    
    # Buat file log dan inisialisasi file lainnya
    touch /var/log/xray/access.log /var/log/xray/error.log
    touch /etc/xray/domain
    curl -s ifconfig.me > /etc/xray/ipvps
    print_success "Direktori dan file"
}

function pasang_domain() {
    clear
    echo -e " .----------------------------------."
    echo -e " | \e[1;32mPilih Tipe Domain di Bawah Ini\e[0m |"
    echo -e " '----------------------------------'"
    echo -e "   \e[1;32m1)\e[0m Gunakan Domain Anda Sendiri"
    echo -e "   \e[1;32m2)\e[0m Gunakan Domain Acak dari Script"
    echo -e " ------------------------------------"
    read -p "   Pilih nomor [1-2]: " host
    echo ""
    if [[ $host == "1" ]]; then
        read -p "   Masukkan Subdomain Anda: " host1
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
    elif [[ $host == "2" ]]; then
        wget -q ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
    else
        print_error "Pilihan tidak valid, instalasi dibatalkan."
        exit 1
    fi
    clear
}

function pasang_ssl() {
    print_install "Memasang SSL Certificate pada Domain"
    domain=$(cat /root/domain)
    if [ -z "$domain" ]; then
        print_error "Domain tidak ditemukan. Pastikan domain sudah diatur."
        exit 1
    fi
    
    systemctl stop nginx
    
    # Gunakan acme.sh untuk SSL
    rm -rf /root/.acme.sh
    curl -sL https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    
    # Mengubah izin file menjadi lebih aman
    chmod 644 /etc/xray/xray.key
    print_success "SSL Certificate"
    systemctl start nginx
}

function install_xray() {
    print_install "Menginstall Xray Core Versi Terbaru"
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version "$latest_version"
    print_success "Xray Core"

    print_install "Memasang Konfigurasi Xray, Nginx, dan HAProxy"
    domain=$(cat /etc/xray/domain)
    
    # Download semua konfigurasi
    wget -qO /etc/xray/config.json "${REPO}config/config.json"
    wget -qO /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf"
    wget -qO /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg"
    wget -qO /etc/nginx/nginx.conf "${REPO}config/nginx.conf"
    
    # Ganti placeholder domain
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg

    # Gabungkan sertifikat untuk HAProxy
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem > /dev/null

    # Buat service Xray
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    print_success "Konfigurasi Packet"
}

function ssh_setup() {
    print_install "Mengkonfigurasi SSH & Sistem"
    
    # Konfigurasi SSHD
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd"
    # Tambah banner ke sshd_config
    sed -i 's/#Banner none/Banner \/etc\/kyt.txt/g' /etc/ssh/sshd_config
    
    # Disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    
    # Konfigurasi rc.local untuk persistensi
    cat > /etc/rc.local <<-END
#!/bin/sh -e
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
exit 0
END
    chmod +x /etc/rc.local
    
    # Buat service rc-local jika belum ada
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
END
    systemctl enable rc-local
    systemctl start rc-local.service
    print_success "Konfigurasi SSH & Sistem"
}

function ins_dropbear() {
    print_install "Menginstall Dropbear"
    apt-get install -y dropbear
    wget -qO /etc/default/dropbear "${REPO}config/dropbear.conf"
    # Tambah banner ke dropbear
    sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/kyt.txt"/' /etc/default/dropbear
    print_success "Dropbear"
}

function ins_openvpn() {
    print_install "Menginstall OpenVPN"
    wget -q ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    print_success "OpenVPN"
}

function ins_vnstat() {
    print_install "Menginstall Vnstat"
    # Vnstat dari repo sudah cukup, tidak perlu kompilasi manual
    apt -y install vnstat
    NET=$(ip -o -4 route show to default | awk '{print $5}')
    sed -i "s/^Interface .*/Interface \"${NET}\"/" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    print_success "Vnstat"
}

function ins_swab() {
    print_install "Memasang Swap 1 GB"
    dd if=/dev/zero of=/swapfile bs=1G count=1
    mkswap /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    print_success "Swap 1 GB"
}

function ins_epro() {
    print_install "Menginstall ePro WebSocket Proxy"
    wget -qO /usr/bin/ws "${REPO}files/ws"
    wget -qO /usr/bin/tun.conf "${REPO}config/tun.conf"
    wget -qO /etc/systemd/system/ws.service "${REPO}files/ws.service"
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    
    # Update GeoIP & GeoSite
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    
    # Aturan Firewall untuk Blokir Torrent
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables-save > /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload
    
    print_success "ePro WebSocket Proxy"
}

function install_menu() {
    print_install "Memasang Menu"
    wget -q ${REPO}menu/menu.zip
    unzip -oq menu.zip -d /usr/local/sbin/
    chmod +x /usr/local/sbin/*
    rm -f menu.zip
    print_success "Menu"
}

function setup_profile_cron() {
    print_install "Menyiapkan Profile dan Jadwal Cron"
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ -f "\$HOME/.bashrc" ]; then
    . "\$HOME/.bashrc"
fi
mesg n || true
welcome
EOF

    # Setup cron jobs
    echo "*/20 * * * * root /usr/local/sbin/clearlog" > /etc/cron.d/logclean
    echo "0 5 * * * root /sbin/reboot" > /etc/cron.d/daily_reboot
    echo "0 0 * * * root /usr/local/sbin/xp" > /etc/cron.d/xp_all
    echo "*/2 * * * * root /usr/local/sbin/limit-ip" > /etc/cron.d/limit_ip
    echo "*/1 * * * * root /usr/local/sbin/limit-ip-ssh" > /etc/cron.d/lim-ip-ssh
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log_nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" > /etc/cron.d/log_xray
    
    chmod 644 /root/.profile /etc/cron.d/*
    
    # Banner
    wget -qO /etc/kyt.txt "${REPO}files/issue.net"
    
    print_success "Profile dan Cron"
}

function send_telegram_notif() {
    # PERINGATAN: Menyimpan API Key di skrip publik sangat tidak aman!
    # Sebaiknya gunakan variabel lingkungan atau metode lain yang lebih aman.
    CHATID="1002598300"
    KEY="6040072616:AAE9c3kp8MLUKiA2Q_CWeXzT6SrLhRz0Mg4"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    
    MYIP=$(curl -sS ipv4.icanhazip.com)
    izinsc="https://raw.githubusercontent.com/xyoruz/X/main/ip"
    username=$(curl -s $izinsc | grep $MYIP | awk '{print $2}')
    exp=$(curl -s $izinsc | grep $MYIP | awk '{print $3}')
    ISP=$(curl -s ipinfo.io/org)
    CITY=$(curl -s ipinfo.io/city)
    
    TEXT="
<code>────────────────────</code>
<b>⚡ SCRIPT INSTALL NOTIFICATION ⚡</b>
<code>────────────────────</code>
<code>User     : </code><code>${username:-N/A}</code>
<code>IP       : </code><code>$MYIP</code>
<code>ISP      : </code><code>$ISP</code>
<code>City     : </code><code>$CITY</code>
<code>Exp Sc.  : </code><code>${exp:-N/A}</code>
<code>────────────────────</code>
<b>XYR VPN STORE SCRIPT</b>
<code>────────────────────</code>"

    curl -s --max-time 10 -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

function restart_all_services() {
    print_install "Merestart dan Mengaktifkan Semua Layanan"
    systemctl daemon-reload
    
    # Daftar layanan untuk diaktifkan dan direstart
    services=("netfilter-persistent" "cron" "nginx" "xray" "dropbear" "openvpn" "vnstat" "ws" "haproxy" "ssh")
    
    for service in "${services[@]}"; do
        systemctl enable --now "$service" >/dev/null 2>&1
        systemctl restart "$service" >/dev/null 2>&1
    done
    
    print_success "Semua layanan"
}

function final_cleanup_and_summary() {
    history -c
    echo "unset HISTFILE" >> /etc/profile
    
    domain=$(cat /etc/xray/domain)
    username=$(curl -s "https://raw.githubusercontent.com/xyoruz/X/main/ip" | grep "$(curl -sS ipv4.icanhazip.com)" | awk '{print $2}')
    hostnamectl set-hostname "${username:-XYR-Tunnel}"

    rm -f /root/{openvpn,key.pem,cert.pem,*.sh,*.zip,LICENSE,README.md,domain}
    apt-get autoremove -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1

    secs_to_human() {
        echo "Waktu Instalasi: $((${1} / 3600)) jam, $(((${1} / 60) % 60)) menit, $((${1} % 60)) detik."
    }
    
    clear
    echo "===============-[ SCRIPT BY XYR TUNNEL ]-==============="
    echo ""
    secs_to_human "$(($(date +%s) - ${start}))"
    echo ""
    echo "------------------------------------------------------------"
    echo " >>> Service & Port"
    echo "------------------------------------------------------------"
    echo "  - OpenSSH               : 22, 53, 2222, 2269"
    echo "  - SSH Websocket         : 80"
    echo "  - SSH SSL Websocket     : 443"
    echo "  - Dropbear              : 109, 143"
    echo "  - Badvpn (UDPGW)        : 7100, 7200, 7300"
    echo "  - Nginx                 : 81"
    echo "  - XRAY VMess/VLess (TLS): 443"
    echo "  - XRAY VMess/VLess (NTLS): 80"
    echo "  - XRAY Trojan (WS/gRPC) : 443"
    echo "  - SlowDNS               : 53"
    echo "------------------------------------------------------------"
    echo " >>> Server Information & Other Features"
    echo "------------------------------------------------------------"
    echo "  - Domain                : $domain"
    echo "  - Timezone              : Asia/Jakarta (GMT +7)"
    echo "  - Auto-Reboot           : 05:00 AM (Dapat diubah di cron)"
    echo "  - IPv6                  : [OFF]"
    echo "  - AutoKill Multi-Login  : [ON]"
    echo "------------------------------------------------------------"
    echo ""
    read -p "Instalasi selesai. Tekan Y untuk reboot sekarang [Y/n]: " answer
    if [[ "$answer" =~ ^[Yy]$ || -z "$answer" ]]; then
        reboot
    fi
}
