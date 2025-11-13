#!/bin/bash
# Version 0.7 14/11/25 2:52  

UN=${SUDO_USER:-$(whoami)}

# --- CONFIG ---
WIFI_INTERFACE="wlan0"
LAN_INTERFACE="eth0" # Internet
SSID="Open-To-All"
CHANNEL="6"
targets_path="/home/$UN/Desktop"
OUI_FILE="$targets_path/oui.txt"
LOG_FILE="$targets_path/AP_clients.log"
AP_IP="192.168.50.1"
DHCP_RANGE_START="192.168.50.10"
DHCP_RANGE_END="192.168.50.11"

# --- COLORS ---
GREEN="\e[32m"
RED="\e[31m"
NC="\e[0m"  # No Color

# --- CLEANUP FUNCTION ---
cleanup() {
    echo -e "\n\n[*] Stopping AP..."
    sudo pkill hostapd
    sudo pkill dnsmasq
    sudo rm -f /var/lib/misc/dnsmasq.leases
    sudo iptables -t nat -D POSTROUTING -o $LAN_INTERFACE -j MASQUERADE
    sudo iptables -D FORWARD -i $LAN_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -D FORWARD -i $WIFI_INTERFACE -o $LAN_INTERFACE -j ACCEPT
    sudo ip link set $WIFI_INTERFACE down
    sudo ip addr flush dev $WIFI_INTERFACE
    sudo systemctl start NetworkManager
    exit 0
}

trap cleanup SIGINT

# --- FUNCTIONS ---
get_name() {
    MAC=$1
    grep -i "$MAC" /var/lib/misc/dnsmasq.leases | awk '{print $4}' || echo "Unknown"
}

get_ip() {
    MAC=$1
    grep -i "$MAC" /var/lib/misc/dnsmasq.leases | awk '{print $3}' || echo "Unknown"
}

check_oui() {
    mkdir -p "$(dirname "$OUI_FILE")"
    if [ ! -f "$OUI_FILE" ]; then
        echo -e "[*] Downloading OUI vendor file..."
        wget -q https://raw.githubusercontent.com/idoCo10/OUI-list/main/oui.txt -O "$OUI_FILE"
        [[ ! -f "$OUI_FILE" ]] && { echo -e "${RED}Failed to download OUI vendor file.${NC}"; exit 1; }
    fi
}

get_oui() {
    MAC=$1
    PREFIX=$(echo "$MAC" | awk -F':' '{print toupper($1 ":" $2 ":" $3)}')
    VENDOR=$(grep -i "^$PREFIX" "$OUI_FILE" | head -n 1 | cut -d' ' -f2-)
    echo "${VENDOR:-Unknown}"
}

# --- Wait for DHCP lease to appear (max 30s) ---
wait_for_dhcp_info() {
    local mac=$1
    local timeout=60
    local elapsed=0
    local ip name

    while [ $elapsed -lt $timeout ]; do
        ip=$(get_ip "$mac")
        name=$(get_name "$mac")
        if [[ -n "$ip" && "$ip" != "Unknown" ]]; then
            echo "$ip|$name"
            return
        fi
        sleep 0.5
        ((elapsed++))
    done

    echo "Unknown|Unknown"
}

# --- Release DHCP IP ---
release_ip() {
    local MAC=$1
    local LEASE_FILE="/var/lib/misc/dnsmasq.leases"

    if [ ! -f "$LEASE_FILE" ]; then
        echo "dnsmasq lease file not found: $LEASE_FILE"
        return
    fi

    local LINE=$(grep -i "$MAC" "$LEASE_FILE")
    if [ -n "$LINE" ]; then
        local IP=$(echo "$LINE" | awk '{print $3}')
        grep -iv "$MAC" "$LEASE_FILE" > /tmp/dnsmasq.leases.tmp && mv /tmp/dnsmasq.leases.tmp "$LEASE_FILE"
        # Reload dnsmasq
        systemctl reload dnsmasq 2>/dev/null || killall -HUP dnsmasq 2>/dev/null
    fi
}

# --- PREPARATION ---
check_oui

echo "[*] Stopping NetworkManager..."
sudo systemctl stop NetworkManager

echo "[*] Setting $WIFI_INTERFACE to AP mode..."
sudo ip link set $WIFI_INTERFACE down
sudo ip addr flush dev $WIFI_INTERFACE
sudo iw dev $WIFI_INTERFACE set type ap 2>/dev/null
sudo ip addr add $AP_IP/24 dev $WIFI_INTERFACE
sudo ip link set $WIFI_INTERFACE up

# --- HOSTAPD CONFIG ---
HOSTAPD_CONF=$(mktemp)
cat <<EOF > $HOSTAPD_CONF
interface=$WIFI_INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
ignore_broadcast_ssid=0
EOF

echo "[*] Starting hostapd..."
sudo hostapd $HOSTAPD_CONF > /dev/null 2>&1 &

# --- DNSMASQ CONFIG ---
DNSMASQ_CONF=$(mktemp)
cat <<EOF > $DNSMASQ_CONF
interface=$WIFI_INTERFACE
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,1h
EOF

echo "[*] Starting dnsmasq..."
sudo dnsmasq -C $DNSMASQ_CONF

# --- NAT/INTERNET SHARING ---
sudo iptables -t nat -A POSTROUTING -o $LAN_INTERFACE -j MASQUERADE
sudo iptables -A FORWARD -i $LAN_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i $WIFI_INTERFACE -o $LAN_INTERFACE -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo -e "[*] AP '$SSID' started on Channel '$CHANNEL'."
echo -e "[*] Waiting for clients:\n\n"

# --- LOGGING ---
touch $LOG_FILE
declare -A CLIENTS

# --- MAIN LOOP ---
while true; do
    STATIONS=$(iw dev $WIFI_INTERFACE station dump | grep Station | awk '{print toupper($2)}')
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

    # --- Detect New Connections ---
    for MAC in $STATIONS; do
        if [[ -z "${CLIENTS[$MAC]}" ]]; then
            DEVICE_INFO=$(wait_for_dhcp_info "$MAC")
            IP=$(echo "$DEVICE_INFO" | cut -d'|' -f1)
            NAME=$(echo "$DEVICE_INFO" | cut -d'|' -f2)
            OUI=$(get_oui "$MAC")

            # Fixed-width formatting
            printf -v MSG "[%s] CONNECTED:    Name: %-9s | IP: %-13s | MAC: %17s | OUI: %s" \
            "$TIMESTAMP" "$NAME" "$IP" "$MAC" "$OUI"

            echo -e "${GREEN}${MSG}${NC}"
            echo "$MSG" >> "$LOG_FILE"
            CLIENTS[$MAC]=1
        fi
    done

    # --- Detect Disconnections ---
    for MAC in "${!CLIENTS[@]}"; do
        if ! echo "$STATIONS" | grep -q "$(echo "$MAC" | tr 'a-z' 'A-Z')"; then
            IP=$(get_ip "$MAC")
            NAME=$(get_name "$MAC")
            OUI=$(get_oui "$MAC")

            printf -v MSG "[%s] DISCONNECTED: Name: %-9s | IP: %-13s | MAC: %17s | OUI: %s" \
            "$TIMESTAMP" "$NAME" "$IP" "$MAC" "$OUI"

            echo -e "${RED}${MSG}${NC}"
            echo "$MSG" >> "$LOG_FILE"
            #release_ip "$MAC"
            unset CLIENTS[$MAC]
        fi
    done

    sleep 0.5
done
