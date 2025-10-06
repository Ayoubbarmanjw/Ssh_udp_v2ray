#!/bin/bash
set -euo pipefail
if [[ $EUID -ne 0 ]];
then
    echo -e "\033[0;31mError: This script must be run as root.\033[0m"
    exit 1
fi
INSTALL_DIR="/opt/tunnel_manager"
MANAGER_SCRIPT="$INSTALL_DIR/main_manager.sh"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
HOST_FILE="/etc/tunnel_host"
XRAY_API_PORT="8081"
XRAY_INBOUND_TAG="vless-in"
DROPBEAR_PORT_MAIN="115"
DROPBEAR_PORT_ALT="109"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
acquire_dynamic_host() {
    echo -e "\n${YELLOW}0. Running Cloudflare Subdomain Acquisition Script (cf)...${NC}"
    wget https://github.com/FasterExE/VIP-Autoscript/raw/refs/heads/main/ssh/cf -O /tmp/cf_script || 
    { echo -e "${RED}Error: Failed to download cf script.${NC}"; exit 1; }
    echo -e "${BLUE}Running cf script. Please ensure Cloudflare credentials are set up...${NC}"
    bash /tmp/cf_script 2>&1 | tee /tmp/cf_output.log
    NEW_HOST=$(grep -i 'Host WS :' /tmp/cf_output.log | awk '{print $3}' | tail -n 1)
    rm -f /tmp/cf_script /tmp/cf_output.log
    if [ -z "$NEW_HOST" ]; then
        echo -e "${RED}Error: Failed to extract a new Host/Domain from the cf script output.${NC}"
        echo -e "${RED}Please ensure the cf script ran successfully and printed 'Host WS :' line.${NC}"
        exit 1
    else
        HOST="$NEW_HOST"
        echo "$HOST" > "$HOST_FILE"
        TLS_CERT_PATH="/etc/letsencrypt/live/$HOST/fullchain.pem"
        TLS_KEY_PATH="/etc/letsencrypt/live/$HOST/privkey.pem"
        echo -e "${GREEN}Successfully acquired and set Host: $HOST${NC}"
        echo -e "${YELLOW}!!! WARNING: You must manually run Certbot to obtain SSL certificates for $HOST !!!${NC}"
    fi
}
install_dependencies() {
    echo -e "\n${YELLOW}1. Installing required dependencies (jq, Nginx, Dropbear)...${NC}"
    local PKG_MANAGER
    if command -v apt &>/dev/null;
then PKG_MANAGER="apt"; 
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf";
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum";
else
        echo -e "${RED}Error: Cannot find a package manager (apt/dnf/yum).${NC}";
exit 1
    fi
    if [ "$PKG_MANAGER" = "apt" ];
then
        apt update && apt install -y dropbear nginx jq
    elif [ "$PKG_MANAGER" = "dnf" ] ||
[ "$PKG_MANAGER" = "yum" ]; then
        "$PKG_MANAGER" install -y dropbear nginx jq
    fi
    echo -e "${GREEN}Dependencies installed successfully.${NC}"
}
install_xray_core() {
    echo -e "\n${YELLOW}2. Starting Xray (VLESS Core) installation...${NC}"
    bash -c "$(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-release/master/install-release.sh)" ||
{ echo -e "${RED}Xray installation failed.${NC}"; exit 1; }
    echo -e "${GREEN}Xray Core installed successfully.${NC}"
}
configure_dropbear_and_ssh() {
    echo -e "\n${YELLOW}3. Configuring Dropbear and SSH for Tunneling...${NC}"
    if [ -f "/etc/default/dropbear" ];
then
        sed -i "s/^NO_START=.*/NO_START=0/g" /etc/default/dropbear
        sed -i "s/^DROPBEAR_PORT=.*/DROPBEAR_PORT=\"${DROPBEAR_PORT_MAIN}\"/g" /etc/default/dropbear
        sed -i "s/^DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS=\"-p ${DROPBEAR_PORT_ALT}\"/g" /etc/default/dropbear
    fi
    systemctl enable dropbear || true
    systemctl restart dropbear || true
    echo -e "\033[0;32mDropbear configured on ports ${DROPBEAR_PORT_MAIN} and ${DROPBEAR_PORT_ALT}.\033[0m"
}
configure_nginx() {
    echo -e "\n${YELLOW}4. Configuring Nginx for WebSocket Tunneling...${NC}"
    local nginx_conf="/etc/nginx/sites-available/tunnel_proxy.conf"
    cat > "$nginx_conf" <<- EOF
server {
    listen 80;
    listen 8880;
    server_name $HOST;
    location /ws {
        proxy_pass http://127.0.0.1:$DROPBEAR_PORT_MAIN;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
server {
    listen 443 ssl;
    listen 8080 ssl;
    server_name $HOST;
    ssl_certificate $TLS_CERT_PATH;
    ssl_certificate_key $TLS_KEY_PATH;
    location /wss {
        proxy_pass http://127.0.0.1:$DROPBEAR_PORT_MAIN;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF
    ln -sf "$nginx_conf" /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t && systemctl restart nginx
    echo -e "\033[0;32mNginx Proxy configured for WS/WSS tunneling on ports 80/443/8080/8880 using Host: $HOST.\033[0m"
}
configure_vless_xray() {
    echo -e "\n${YELLOW}5. Configuring Xray (VLESS) initial template...${NC}"
    mkdir -p /usr/local/etc/xray/
    cat > "$XRAY_CONFIG" <<- EOF
{
  "log": {"loglevel": "warning"},
  "stats": {},
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService"],
    "address": "127.0.0.1",
    "port": $XRAY_API_PORT
  },
  "policy": {
    "levels": {"0": {"handshake": 4, 
"connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 2, "bufferSize": 1024}}
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
     
"alpn": ["http/1.1"],
          "certificates": [
            {"certificateFile": "$TLS_CERT_PATH", "keyFile": "$TLS_KEY_PATH"}
          ]
        },
        "wsSettings": {
          "path": "/$XRAY_INBOUND_TAG"
        }
      },
      "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
     
"tag": "$XRAY_INBOUND_TAG"
    }
  ],
  "outbounds": [{"protocol": "freedom", "settings": {}, "tag": "direct"}]
}
EOF
    systemctl enable xray || true
    systemctl restart xray
    echo -e "\033[0;32mVLESS template configured and service restarted (Host: $HOST).\033[0m"
}
main_installer() {
    echo -e "\n${CYAN}========================================================${NC}"
    echo -e "${BOLD}${GREEN}Starting All-in-One Tunneling System Setup...${NC}"
    echo -e "${CYAN}========================================================${NC}"
    acquire_dynamic_host
    install_dependencies
    install_xray_core
    configure_dropbear_and_ssh
    configure_nginx
    configure_vless_xray
    mkdir -p "$INSTALL_DIR"
    cat > "$MANAGER_SCRIPT" <<- 'EOF_MANAGER'
#!/bin/bash
set -euo pipefail
if [[ $EUID -ne 0 ]];
then
    echo -e "\033[0;31mError: This script must be run as root.\033[0m"
    exit 1
fi
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
BLINK='\033[5m'
IP="209.38.109.192"
HOST_FILE="/etc/tunnel_host"
DEFAULT_HOST="we-v7etl-udp.hscript1.my.id (DEFAULT)"
HOST=$(cat "$HOST_FILE" 2>/dev/null || echo "$DEFAULT_HOST")
if [ "$HOST" = "$DEFAULT_HOST" ]; then
    echo -e "${RED}WARNING: Dynamic Host file ($HOST_FILE) not found. Using default value. Please run installer.sh!${NC}"
fi
DROPBEAR_PORT_MAIN="115"
DROPBEAR_PORT_ALT="109"
VPN_PORT="5000" 
LOGIN_LIMIT_FILE="/etc/ssh_user_limits"
DELETION_TRACKER_FILE="/etc/ssh_multi_delete_tracker"
SERVER_EXPIRY_DATE_FILE="/etc/server_expiry_date"
DELETION_LOG="/var/log/dropbear_user_deletions.log"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
VLESS_LIMIT_FILE="/etc/vless_user_limits"
XRAY_API_PORT="8081"
XRAY_INBOUND_TAG="vless-in"
TLS_CERT_PATH="/etc/letsencrypt/live/$HOST/fullchain.pem"
TLS_KEY_PATH="/etc/letsencrypt/live/$HOST/privkey.pem"
setup_secure_files() {
    if [ !
-f "$SERVER_EXPIRY_DATE_FILE" ]; then
        date -d "+30 days" +%Y-%m-%d > "$SERVER_EXPIRY_DATE_FILE"
    fi
    touch "$LOGIN_LIMIT_FILE" "$DELETION_TRACKER_FILE" "$DELETION_LOG" "$VLESS_LIMIT_FILE"
    chmod 600 "$LOGIN_LIMIT_FILE" "$DELETION_TRACKER_FILE" "$VLESS_LIMIT_FILE"
    chmod 644 "$DELETION_LOG"
}
setup_secure_files
get_server_expiry() {
    if [ -f "$SERVER_EXPIRY_DATE_FILE" ];
then cat "$SERVER_EXPIRY_DATE_FILE"; else echo "Not Set"; fi
}
check_and_enforce_server_expiry() {
    local expiry_date; expiry_date=$(get_server_expiry)
    local today_sec;
today_sec=$(date +%s)
    local expiry_sec; expiry_sec=$(date -d "$expiry_date" +%s 2>/dev/null)
    if [ !
-z "$expiry_sec" ] && (( expiry_sec <= today_sec )); then
        echo -e "${RED}==========================================\nSECURITY WARNING: Server subscription expired.\n==========================================${NC}";
exit 1
    fi
    local warning_date;
warning_date=$(date -d "+7 days" +%s)
    if [ ! -z "$expiry_sec" ] && (( expiry_sec <= warning_date ));
then
        local days_left;
days_left=$(( (expiry_sec - today_sec) / 86400 ))
        echo -e "${YELLOW}WARNING: Server license expires in ${days_left} day(s)!${NC}"
    fi
}
check_and_enforce_server_expiry
display_banner() {
    clear
    echo -e "${GREEN}\n=========================================="
    echo "       TUNNELING SERVER MANAGEMENT         "
    echo "=========================================="
    echo -e "${YELLOW}Server Expiry: $(get_server_expiry)${NC}"
    echo "=========================================="
    echo -e "${NC}"
}
validate_username() {
    local username="$1"
    if [[ "$username" =~ [^a-zA-Z0-9._-] ]] 
|| [ ${#username} -lt 3 ] || [ ${#username} -gt 32 ];
then
        echo -e "${RED}Error: Invalid username. (3-32 chars, no spaces/special chars).${NC}"
        return 1
    fi
    return 0
}
install_and_config_dropbear() {
    display_banner
    echo -e "${YELLOW}Setting up Dropbear and Ports for Tunneling${NC}"
    local PKG_MANAGER
    if command -v apt &>/dev/null;
then PKG_MANAGER="apt"; 
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf";
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum";
fi
    if [ "$PKG_MANAGER" = "apt" ];
then
        apt update && apt install -y dropbear
    elif [ "$PKG_MANAGER" = "dnf" ] ||
[ "$PKG_MANAGER" = "yum" ]; then
        "$PKG_MANAGER" install -y dropbear
    fi
    echo -e "${BLUE}Configuring Dropbear to listen on ports ${DROPBEAR_PORT_MAIN} and ${DROPBEAR_PORT_ALT}...${NC}"
    if [ -f "/etc/default/dropbear" ];
then
        sed -i "s/^NO_START=.*/NO_START=0/g" /etc/default/dropbear
        sed -i "s/^DROPBEAR_PORT=.*/DROPBEAR_PORT=\"${DROPBEAR_PORT_MAIN}\"/g" /etc/default/dropbear
        sed -i "s/^DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS=\"-p ${DROPBEAR_PORT_ALT}\"/g" /etc/default/dropbear
    fi
    systemctl restart dropbear ||
true
    echo -e "${GREEN}Dropbear configured successfully!${NC}"
    echo "=================================================="
    echo "Dropbear Ports (TCP): ${DROPBEAR_PORT_MAIN}, ${DROPBEAR_PORT_ALT}"
    echo "Fake UDP Port (If configured separately): ${VPN_PORT}"
    echo "=================================================="
    read -p "Press Enter to continue..."
}
create_ssh_user() {
    display_banner
    echo -e "${YELLOW}Create New Tunnel Account (Dropbear/SSH)${NC}"
    local username password expiry_days limit expiry_date expiry_display
    while true;
do read -p "Enter Username: " username; if validate_username "$username"; then if id "$username" &>/dev/null;
then echo -e "${RED}User $username already exists!${NC}"; else break; fi; fi;
done
    read -s -p "Enter Password: " password; echo
    while true;
do read -p "Validity Period (Days): " expiry_days; if [[ "$expiry_days" =~ ^[1-9][0-9]*$ ]]; then break;
else echo -e "${RED}Please enter a valid positive number of days!${NC}"; fi; done
    while true;
do read -p "Maximum Concurrent Users: " limit; if [[ "$limit" =~ ^[1-9][0-9]*$ ]]; then break;
else echo -e "${RED}Please enter a valid positive number for the limit!${NC}"; fi;
done
    useradd -m -s /bin/bash "$username"
    echo "$username:$password" |
chpasswd
    expiry_date=$(date -d "+$expiry_days days" +"%Y-%m-%d"); expiry_display=$(date -d "$expiry_date" +"%b %d, %Y")
    chage -E "$expiry_date" "$username"
    sed -i "/^$username,/d" "$LOGIN_LIMIT_FILE" 2>/dev/null ||
true
    echo "$username,$limit" >> "$LOGIN_LIMIT_FILE"
    cat > /home/"$username"/.profile <<- EOF
USER_LIMIT=\$(grep "^$USER," /etc/ssh_user_limits 2>/dev/null | cut -d, -f2)
CURRENT_SESSIONS=\$(who | grep -w "\$USER" | wc -l)
RED='\033[0;31m';
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'; BLINK='\033[5m'
if [ -n "\$USER_LIMIT" ] && [ "\$USER_LIMIT" -ne 0 ] && [ "\$CURRENT_SESSIONS" -gt "\$USER_LIMIT" ];
then
    echo -e "\${RED}\${BOLD}\${BLINK}========================================================================\${NC}"
    echo -e "\${RED}\${BOLD}                                🚨 تـنـبـيـه خـطـر 🚨                                \${NC}"
    echo -e "\${RED}${BOLD}========================================================================${NC}"
    echo -e "\${RED}\${BOLD}   لقد تجاوزت الحد الأقصى للجلسات المسموح 
به (\$USER_LIMIT).\n"
    echo -e "\${RED}\${BOLD}   الرجاء التأكد من عدم استخدام الحساب على أكثر من جهاز (\$USER_LIMIT/\$CURRENT_SESSIONS).\${NC}"
    echo -e "\${RED}\${BOLD}========================================================================\${NC}"
    exit 0
else
    echo -e "\${GREEN}\${BOLD}=====================================================\${NC}"
    echo -e "\${CYAN}\${BOLD}       ✨ حساب نفق الدروبير / UDP السريع ✨\${NC}"
    echo -e "\${GREEN}\${BOLD}=====================================================\${NC}"
    echo -e "\${YELLOW}  اسم المستخدم:\${NC} \$USER"
    echo -e "\${YELLOW}  الجلسات المسموح بها:\${NC} \$CURRENT_SESSIONS / \$USER_LIMIT"
    echo -e "\${GREEN}-----------------------------------------------------"
    echo -e "\${RED}🚫 يرجى 
استخدام الحساب في الأغراض المشروعة فقط. 🚫"
    echo -e "\${GREEN}\n  ✨ نرجو لكم استخداماً سعيداً ✨"
    echo -e "\${GREEN}=====================================================\${NC}"
fi
EOF
    chown "$username":"$username" /home/"$username"/.profile
    chmod 755 /home/"$username"/.profile
    echo -e "${GREEN}Account created successfully!${NC}"
    echo "================ SERVER INFO ================"
    echo "Username: $username"
    echo "Password: $password"
    echo "Expiry Date: $expiry_display"
    echo "Login Limit: $limit"
    echo "----------------------------------------"
    echo "IP: $IP"
    echo "Host: 
$HOST"
    echo "Dropbear Ports: ${DROPBEAR_PORT_MAIN}, ${DROPBEAR_PORT_ALT}"
    echo "Fake UDP/VPN Port: ${VPN_PORT}"
    echo "==========================================="
    read -p "Press Enter to continue..."
}
monitor_and_list_users() {
    display_banner
    echo -e "${YELLOW}1.
Active Sessions Summary (Login Limits)${NC}"
    echo "========================================"
    printf "%-15s %-10s %-15s %-10s\n" "USERNAME" "SESSIONS" "LIMIT" "EXPIRES ON"
    echo "----------------------------------------"
    local active_users; active_users=$(grep -E ":/bin/bash" /etc/passwd | cut -d: -f1 | grep -v 'root')
    local all_sessions; all_sessions=$(who | awk '{print $1}')
    for username in $active_users; do
        local expiry_info; expiry_info=$(chage -l "$username" 2>/dev/null | grep "Account expires" | awk '{print $4, $5, $6}')
        local expiry_date; expiry_date=${expiry_info:-"never"}
        local limit; limit=$(grep "^$username," "$LOGIN_LIMIT_FILE" 2>/dev/null | cut -d, -f2)
        local login_limit; login_limit=${limit:-"Unlimited"}
        local current_sessions; current_sessions=$(echo "$all_sessions" | grep -w "$username" | wc -l)
        printf "%-15s %-10s %-15s %-10s\n" "$username" "$current_sessions" "$login_limit" "$expiry_date"
    done
    echo "========================================"
    read -p "Enter Username to view detailed IPs (or press Enter to exit): " username_check
    if [ -n "$username_check" ];
then
        display_banner
        echo -e "${YELLOW}Active IP Details for User $username_check${NC}"
        echo "========================================"
        if id "$username_check" &>/dev/null;
then
            who | grep -w "$username_check" |
awk '{print ">> IP: " $5 " | TTY: " $2 " | Logged in: " $3 " " $4}'
        else
            echo -e "${RED}User $username_check does not exist or has no active sessions.${NC}"
        fi
    fi
    echo "========================================"
    read -p "Press Enter to continue..."
}
delete_ssh_user() {
    display_banner
    echo -e "${YELLOW}Delete Tunnel Account${NC}"
    echo -e "${BLUE}Current Users (Shell: /bin/bash):${NC}"
    grep -E ":/bin/bash" /etc/passwd |
cut -d: -f1 | grep -v 'root'
    echo "================================"
    read -p "Enter Username to Delete: " username
    if id "$username" &>/dev/null;
then
        userdel -r "$username"
        sed -i "/^$username,/d" "$LOGIN_LIMIT_FILE" 2>/dev/null ||
true
        sed -i "/^$username,/d" "$DELETION_TRACKER_FILE" 2>/dev/null ||
true
        echo -e "${GREEN}User $username deleted successfully.${NC}"
    else
        echo -e "${RED}User $username does not exist!${NC}"
    fi
    read -p "Press Enter to continue..."
}
lock_ssh_account() {
    display_banner;
read -p "Enter Username to Lock: " username
    if id "$username" &>/dev/null; then usermod -L "$username";
echo -e "${GREEN}Account $username locked successfully. Cannot log in.${NC}"; else echo -e "${RED}User $username does not exist!${NC}";
fi
    read -p "Press Enter to continue..."
}
unlock_ssh_account() {
    display_banner;
read -p "Enter Username to Unlock: " username
    if id "$username" &>/dev/null; then usermod -U "$username";
echo -e "${GREEN}Account $username unlocked successfully. Can log in.${NC}"; else echo -e "${RED}User $username does not exist!${NC}";
fi
    read -p "Press Enter to continue..."
}
setup_xray_config() {
    display_banner
    echo -e "${YELLOW}Setting up Xray Core Configuration...${NC}"
    if !
command -v jq &> /dev/null; then echo -e "${RED}Error: jq is required. Please install it.${NC}";
read -p "Press Enter to continue..."; return; fi
    local PKG_MANAGER
    if command -v apt &>/dev/null;
then PKG_MANAGER="apt"; 
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf";
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum";
fi
    if [ "$PKG_MANAGER" = "apt" ]; then apt update && apt install -y jq;
elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then "$PKG_MANAGER" install -y jq;
fi
    mkdir -p /usr/local/etc/xray/
    cat > "$XRAY_CONFIG" <<- EOF
{
  "log": {"loglevel": "warning"}, "stats": {},
  "api": {"tag": "api", "services": ["HandlerService", "StatsService"], "address": "127.0.0.1", "port": $XRAY_API_PORT},
  "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 2, "bufferSize": 1024}}},
  "inbounds": [
    {
      "port": 443, "protocol": "vless", "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {
        "network": "ws", "security": "tls", "tlsSettings": {
          "alpn": ["http/1.1"], "certificates": [
        {"certificateFile": "$TLS_CERT_PATH", "keyFile": "$TLS_KEY_PATH"}
          ]},
        "wsSettings": {"path": "/$XRAY_INBOUND_TAG"}
      },
      "sniffing": {"enabled": true, "destOverride": ["http", "tls"]},
      "tag": "$XRAY_INBOUND_TAG"
    }
  ],
  "outbounds": [{"protocol": "freedom", "settings": {}, "tag": "direct"}]
}
EOF
    systemctl enable xray 2>/dev/null ||
true
    systemctl restart xray
    echo -e "${GREEN}Xray configured and restarted (Host: $HOST). Please ensure ports 443/8081 are open.${NC}"
    read -p "Press Enter to continue..."
}
create_vless_user() {
    display_banner
    echo -e "${YELLOW}Create New VLESS Account (UUID)${NC}"
    local new_uuid;
new_uuid=$(cat /proc/sys/kernel/random/uuid)
    while true; do read -p "Validity Period (Days): " expiry_days;
if [[ "$expiry_days" =~ ^[1-9][0-9]*$ ]]; then break; else echo -e "${RED}Please enter a valid positive number of days!${NC}"; fi;
done
    local data_limit_gb
    while true;
do read -p "Data Limit (GB, 0 for Unlimited): " data_limit_gb; if [[ "$data_limit_gb" =~ ^[0-9]+$ ]]; then break;
else echo -e "${RED}Please enter a valid number (GB)!${NC}"; fi;
done
    local clients_path='(.inbounds[] | select(.tag == "'"$XRAY_INBOUND_TAG"'").settings.clients) |= .
+ [{"id": "'"$new_uuid"'", "level": 0}]'
    jq "$clients_path" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    local expiry_date;
expiry_date=$(date -d "+$expiry_days days" +"%Y-%m-%d")
    local expiry_display;
expiry_display=$(date -d "$expiry_date" +"%b %d, %Y")
    echo "$new_uuid,$expiry_date,$data_limit_gb" >> "$VLESS_LIMIT_FILE"
    systemctl reload xray 2>/dev/null ||
true
    local vless_link="vless://${new_uuid}@${HOST}:443?type=ws&security=tls&path=%2F${XRAY_INBOUND_TAG}&host=${HOST}#${new_uuid}"
    echo -e "${GREEN}Account created and added to Xray!${NC}"
    echo "================ VLESS INFO ================"
    echo "UUID: ${BOLD}${new_uuid}${NC}"
    echo "Expiry Date: ${expiry_display}"
    echo "Data Limit: ${data_limit_gb} GB"
    echo "----------------------------------------"
    echo "Host: $HOST"
    echo "Connection Link (VLESS-WS-TLS):"
    echo -e "${CYAN}${vless_link}${NC}"
    echo "==========================================="
    read -p "Press Enter to continue..."
}
monitor_vless_users() {
    display_banner
    echo -e "${YELLOW}Active VLESS Users & Status${NC}"
    echo "========================================"
    printf "%-38s %-12s %-12s %-15s\n" "UUID" "EXPIRES ON" "LIMIT (GB)" "USAGE (GB)"
    echo "----------------------------------------------------------------------------------"
    get_usage_stat() { echo 0;
}
    while IFS=',' read -r uuid expiry_date limit_gb;
do
        if [ -z "$uuid" ]; then continue;
fi
        local usage_gb;
usage_gb=$(get_usage_stat "$uuid")
        local expiry_display;
expiry_display=$(date -d "$expiry_date" +"%b %d")
        local limit_display;
limit_display=${limit_gb:-"Unlimited"}
        printf "%-38s %-12s %-12s %-15s\n" "$uuid" "$expiry_display" "$limit_display" "$usage_gb"
    done < "$VLESS_LIMIT_FILE"
    echo "========================================"
    read -p "Press Enter to continue..."
}
delete_vless_user() {
    display_banner
    echo -e "${YELLOW}Delete VLESS Account${NC}"
    echo -e "${BLUE}Current UUIDs (Partial):${NC}"
    cut -d, -f1 "$VLESS_LIMIT_FILE" |
head -n 10
    echo "================================"
    read -p "Enter UUID to Delete: " target_uuid
    if grep -q "^$target_uuid," "$VLESS_LIMIT_FILE";
then
        local clients_path='(.inbounds[] | select(.tag == "'"$XRAY_INBOUND_TAG"'").settings.clients) |= map(select(.id != "'"$target_uuid"'"))'
        jq "$clients_path" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
        sed -i "/^$target_uuid,/d" "$VLESS_LIMIT_FILE"
        systemctl reload xray 2>/dev/null ||
true
        echo -e "${GREEN}UUID $target_uuid deleted successfully.${NC}"
    else
        echo -e "${RED}UUID $target_uuid not found!${NC}"
    fi
    read -p "Press Enter to continue..."
}
delete_expired_users_auto() {
    TODAY=$(date +%s)
    for user in $(grep -E ":/bin/bash" /etc/passwd | cut -d: -f1 | grep -v 'root');
do
        EXPIRY_DATE_STR=$(chage -l "$user" | grep "Account expires" | awk '{print $4, $5, $6}')
        if [ "$EXPIRY_DATE_STR" != "never" ] && [ !
-z "$EXPIRY_DATE_STR" ]; then
            EXPIRY_DATE_SEC=$(date -d "$EXPIRY_DATE_STR" +%s)
            if (( EXPIRY_DATE_SEC <= TODAY ));
then
                echo "$(date) [SSH/DROPBEAR EXPIRED] Deleted user: $user (Expired on: $EXPIRY_DATE_STR)" >> "$DELETION_LOG"
                userdel -r "$user"
                sed -i "/^$user,/d" "$LOGIN_LIMIT_FILE" 2>/dev/null ||
true
                sed -i "/^$user,/d" "$DELETION_TRACKER_FILE" 2>/dev/null ||
true
            fi
        fi
    done
}
enforce_login_limits() {
    local users_to_delete=""
    if [ !
-f "$LOGIN_LIMIT_FILE" ]; then return; fi
    while IFS=',' read -r username limit;
do
        if [ -z "$username" ] || [ -z "$limit" ]; then continue;
fi
        local current_sessions;
current_sessions=$(who | grep -w "$username" | wc -l)
        if (( current_sessions > limit ));
then
            local sessions_to_kill=$((current_sessions - limit))
            local sessions_list;
sessions_list=$(who | grep -w "$username" | sort -r -k 6)
            echo "$sessions_list" |
head -n "$sessions_to_kill" | while IFS= read -r line; do
                tty=$(echo "$line" | awk '{print $2}')
                pids=$(pgrep -u "$username" -t "$tty")
                if [ !
-z "$pids" ]; then kill -9 $pids 2>/dev/null || true;
fi
            done
            local tracker_info;
tracker_info=$(grep "^$username," "$DELETION_TRACKER_FILE" | head -n 1 || true)
            if [ -z "$tracker_info" ];
then
                local delete_date;
delete_date=$(date -d "+1 day" +%Y-%m-%d)
                echo "$username,$current_sessions,$delete_date" >> "$DELETION_TRACKER_FILE"
            else
                local delete_date;
delete_date=$(echo "$tracker_info" | cut -d, -f3)
                local today;
today=$(date +%Y-%m-%d)
                if [ "$delete_date" == "$today" ];
then users_to_delete+="$username "; fi
                sed -i "s/^$username,.*,/$username,$current_sessions,/" "$DELETION_TRACKER_FILE" ||
true
            fi
        else
            sed -i "/^$username,/d" "$DELETION_TRACKER_FILE" 2>/dev/null ||
true
        fi
    done < "$LOGIN_LIMIT_FILE"
    for del_user in $users_to_delete;
do
        echo "$(date) [SSH LIMIT VIOLATION] Deleted user: $del_user (Continuous over-limit)" >> "$DELETION_LOG"
        userdel -r "$del_user"
        sed -i "/^$del_user,/d" "$LOGIN_LIMIT_FILE" 2>/dev/null ||
true
        sed -i "/^$del_user,/d" "$DELETION_TRACKER_FILE" 2>/dev/null ||
true
    done
}
enforce_vless_limits_auto() {
    TODAY=$(date +%s)
    local active_uuids=""
    local active_clients_json="[]"
    while IFS=',' read -r uuid expiry_date limit_gb;
do
        if [ -z "$uuid" ]; then continue;
fi
        local expiry_sec;
expiry_sec=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
        if (( expiry_sec > 0 )) && (( expiry_sec <= TODAY ));
then
            echo "$(date) [VLESS EXPIRED] Deleted UUID: $uuid (Expired on: $expiry_date)" >> "$DELETION_LOG"
            continue
        fi
active_uuids="$active_uuids $uuid"
        active_clients_json=$(echo "$active_clients_json" | jq --arg id "$uuid" '. += [{"id": $id, "level": 0}]')
    done < "$VLESS_LIMIT_FILE"
    if [ -f "$XRAY_CONFIG" ];
then
        local clients_path='(.inbounds[] | select(.tag == "'"$XRAY_INBOUND_TAG"'").settings.clients) = '"$active_clients_json"
        jq "$clients_path" "$XRAY_CONFIG" > "${XRAY_CONFIG}.tmp" && mv "${XRAY_CONFIG}.tmp" "$XRAY_CONFIG"
    fi
    local temp_file;
temp_file=$(mktemp)
    grep -E "$(echo "$active_uuids" | sed 's/ /\n/g' | tr '\n' '|' | sed 's/|$//')" "$VLESS_LIMIT_FILE" > "$temp_file" ||
true
    mv "$temp_file" "$VLESS_LIMIT_FILE"
    systemctl reload xray 2>/dev/null ||
true
}
main_menu() {
    while true; do
        enforce_login_limits
        delete_expired_users_auto
        enforce_vless_limits_auto
        display_banner
        echo -e "${BLUE}MANAGEMENT MENU${NC}"
        echo -e "${GREEN}[11]${NC} ${YELLOW}Setup Dropbear Ports (Essential)${NC}"
        echo -e "${GREEN}[12]${NC} ${YELLOW}Setup Xray/VLESS Base Configuration${NC}"
        echo "--------------------------------"
        echo -e "${GREEN}[1]${NC} Create SSH/Dropbear User"
        echo -e "${GREEN}[2]${NC} Monitor SSH/Dropbear Users"
        echo -e "${GREEN}[3]${NC} Delete SSH/Dropbear User"
        echo -e "${GREEN}[4]${NC} Lock SSH/Dropbear Account"
        echo -e "${GREEN}[5]${NC} Unlock SSH/Dropbear Account"
        echo "--------------------------------"
        echo -e "${GREEN}[6]${NC} Create VLESS User (UUID)"
        echo -e "${GREEN}[7]${NC} Monitor VLESS Users"
        echo -e "${GREEN}[8]${NC} Delete VLESS User"
        echo "--------------------------------"
        echo -e "${GREEN}[0]${NC} Exit"
        echo "================================"
        read -p "Select Option: " choice
        case $choice in
            1) create_ssh_user ;;
2) monitor_and_list_users ;;
            3) delete_ssh_user ;;
            4) lock_ssh_account ;;
            5) unlock_ssh_account ;;
            6) create_vless_user ;;
            7) monitor_vless_users ;;
8) delete_vless_user ;;
            11) install_and_config_dropbear ;;
            12) setup_xray_config ;;
            0) 
                echo -e "${YELLOW}Exiting script...${NC}"
                exit 0
                ;;
*)
                echo -e "${RED}Invalid option!${NC}"
                read -p "Press Enter to try again..."
                ;;
esac
    done
}
EOF_MANAGER
    chmod +x "$MANAGER_SCRIPT"
    cat > /usr/local/bin/menu <<- EOF
#!/bin/bash
bash "$MANAGER_SCRIPT"
EOF
    chmod +x /usr/local/bin/menu
    echo -e "\n${CYAN}========================================================${NC}"
    echo -e "${BOLD}${GREEN}INSTALLATION COMPLETE!${NC}"
    echo -e "\n${BOLD}To launch the management menu, run:${NC}"
    echo -e "${YELLOW}   menu${NC}"
    echo -e "\n\033[0;31m!!! CRITICAL WARNING: Host $HOST is set. Please run Certbot for SSL. !!!\033[0m"
    echo -e "${CYAN}========================================================${NC}"
}
installer_function() {
    main_installer
}
case "$1" in
    get)
        installer_function
        ;;
    *)
        installer_function
        ;;
esac
