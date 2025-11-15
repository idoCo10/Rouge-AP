#!/bin/bash
# Version 1.3 15/11/25 13:20

UN=${SUDO_USER:-$(whoami)}

# --- CONFIG ---
SSID="OOOpen"
CHANNEL="6"    # Supports 2.4GHz and 5GHz. You can leave empty
AP_MAC=""      # You can leave empty
COUNTRY="TH"   # set your country here its important for RESTRICTED and DFS channels. You can leave empty.
                

WIFI_INTERFACE="wlan0"
LAN_INTERFACE="eth0"   # Internet
targets_path="/home/$UN/Desktop"
OUI_FILE="$targets_path/oui.txt"
LOG_FILE="$targets_path/AP_clients.log"
AP_IP="192.168.50.1"
DHCP_RANGE_START="192.168.50.10"
DHCP_RANGE_END="192.168.50.20"


# --- COLORS ---
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"  
BLUE="\e[34m"
ORANGE=$'\033[1;33m'
RESET="\e[0m"  # No Color



# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script as root or with sudo.${RESET}"
    exit 1
fi


install_dependencies() {

    DEPS=(hostapd dnsmasq iw iproute2 macchanger wget iptables procps)
    MISSING=()

    # Detect missing packages
    for pkg in "${DEPS[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            echo -e "${RED}[!] Missing: $pkg${RESET}"
            MISSING+=("$pkg")
        fi
    done

    # Install only missing ones
    if [ ${#MISSING[@]} -gt 0 ]; then
        echo -e "\n[*] Installing missing packages: ${MISSING[*]}\n"
        sudo apt update -y > /dev/null 2>&1
        sudo apt install -y "${MISSING[@]}"
    else
        echo -e "${GREEN}[✓] All dependencies already installed.${RESET}"
    fi
}


# --- HARDWARE CHECK ---
hardware_check() {
    if ! ip link show "$WIFI_INTERFACE" > /dev/null 2>&1; then
        echo -e "${RED}[!] Interface $WIFI_INTERFACE not found${RESET}"
        return 1
    fi

    if iw list 2>/dev/null | grep -q "AP"; then
        echo -e "${GREEN}[✓] Interface supports AP mode${RESET}"
    else
        echo -e "${RED}[!] Interface may not support AP mode${RESET}"
        return 1
    fi
    return 0
}

# --- CHANNEL CHECK (USES GLOBAL VARIABLES) ---
channel_check() {

    # Get current regulatory domain
    local current_reg
    current_reg=$(iw reg get 2>/dev/null | grep "country" | head -1 | awk '{print $2}' | sed 's/://')
    echo -e "[*] Current regulatory country: ${current_reg:-Not set}"

    # --- Set default country if not specified ---
    if [[ -z "$COUNTRY" ]]; then
        echo "[*] No country specified, defaulting to '00' (world regulatory domain)"
        COUNTRY="00"
    fi

    # Set country only if different
    if [[ "$current_reg" != "$COUNTRY" ]]; then
        echo -e "[*] Changing regulatory country to $COUNTRY..."
        sudo iw reg set "$COUNTRY" > /dev/null 2>&1
    fi

    # Get allowed channels
    local allowed_channels dfs_channels
    allowed_channels=$(iw list | grep -A10 "Frequencies:" | grep -oP '\[\K[0-9]+(?=\])')
    dfs_channels=$(iw list | grep -A10 "Frequencies:" | grep "radar detection" | grep -oP '\[\K[0-9]+(?=\])')

    # Validate channel
    if ! echo "$allowed_channels" | grep -qw "$CHANNEL"; then
        echo -e "${RED}[!] Channel $CHANNEL is not allowed in country: $COUNTRY${RESET}"
        return 1
    fi

    if echo "$dfs_channels" | grep -qw "$CHANNEL"; then
        echo -e "${RED}[!] Channel $CHANNEL is DFS (requires radar detection). Stopping.${RESET}"
        return 1
    fi

    echo -e "${GREEN}[✓] Channel $CHANNEL is valid and allowed in "$COUNTRY".${RESET}"
    return 0
}


# --- Randomize 2.4GHz channel if not set ---
if [[ -z "$CHANNEL" ]]; then
    echo "[*] No channel specified, randomizing 2.4GHz channel..."

    # Get allowed 2.4GHz channels for this country (non-DFS)
    allowed_channels=$(iw list | grep -A10 "Frequencies:" \
                      | grep -v "radar detection" \
                      | grep -oP '\[\K[0-9]+(?=\])' \
                      | awk '$1>=1 && $1<=14')  # limit to 2.4GHz
    if [[ -z "$allowed_channels" ]]; then
        echo "[!] Could not determine allowed 2.4GHz channels. Defaulting to 6."
        CHANNEL=6
    else
        # Pick a random channel from the allowed ones
        CHANNEL=$(echo "$allowed_channels" | shuf -n1)
    fi
    echo "[*] Random channel selected: $CHANNEL"
fi



# --- CLEANUP FUNCTION ---
cleanup() {
    echo -e "\n\n[*] Stopping AP..."
    sudo pkill hostapd
    sudo rm -f /tmp/hostapd.conf
    sudo pkill dnsmasq
    sudo rm -f /var/lib/misc/dnsmasq.leases
    sudo iptables -t nat -D POSTROUTING -o $LAN_INTERFACE -j MASQUERADE
    sudo iptables -D FORWARD -i $LAN_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -D FORWARD -i $WIFI_INTERFACE -o $LAN_INTERFACE -j ACCEPT
    sudo ip link set $WIFI_INTERFACE down
    sudo ip addr flush dev $WIFI_INTERFACE
    sudo iw dev $WIFI_INTERFACE set type managed 2>/dev/null
    sudo ip link set $WIFI_INTERFACE up
    sudo systemctl start NetworkManager
    echo -e "${GREEN}[✓] Cleanup complete - Wi-Fi interface restored to normal mode${RESET}"
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
        [[ ! -f "$OUI_FILE" ]] && { echo -e "${RED}Failed to download OUI vendor file.${RESET}"; exit 1; }
    fi
}

get_oui() {
    MAC=$1
    PREFIX=$(echo "$MAC" | awk -F':' '{print toupper($1 ":" $2 ":" $3)}')
    VENDOR=$(grep -i "^$PREFIX" "$OUI_FILE" | head -n 1 | cut -d' ' -f2-)
    echo "${VENDOR:-Unknown}"
}

set_ap_mac() {
    local iface="$WIFI_INTERFACE"

    # --- CASE 1: AP_MAC is empty → randomize MAC ---
    if [[ -z "$AP_MAC" ]]; then
        echo -e "[*] No AP MAC specified — randomizing MAC:"

        # Bring interface down
        sudo ip link set "$iface" down

        # Get permanent MAC
        local perm_output
        perm_output=$(macchanger -p "$iface" 2>/dev/null)
        local perm_mac
        perm_mac=$(echo "$perm_output" | awk -F': ' '/Permanent MAC:/ {print toupper($2)}' | cut -d' ' -f1)

        # Vendor
        local perm_vendor
        perm_vendor=$(get_oui "$perm_mac")

        # Randomize MAC
        local rand_output
        rand_output=$(macchanger -r "$iface" 2>/dev/null)
        local rand_mac
        rand_mac=$(echo "$rand_output" | awk -F': ' '/New MAC:/ {print toupper($2)}' | cut -d' ' -f1)

        # Fallback if parsing fails
        if [[ -z "$rand_mac" ]]; then
            rand_mac=$(ip link show "$iface" | awk '/link\/ether/ {print toupper($2)}')
        fi

        # Vendor
        local rand_vendor
        rand_vendor=$(get_oui "$rand_mac")

        # Bring interface up
        sudo ip link set "$iface" up

        # Output
        echo -e "      Permanent MAC:  $perm_mac   ($perm_vendor)"
        echo -e "${GREEN}    ✓ Randomized MAC: $rand_mac   ($rand_vendor)${RESET}"
        return
    fi

    # --- CASE 2: AP_MAC is provided → use it ---
    local mac="$AP_MAC"

    sudo ip link set "$iface" down
    sudo ip link set dev "$iface" address "$mac"
    sudo ip link set "$iface" up

    # Verify
    local new_mac
    new_mac=$(ip link show "$iface" | awk '/link\/ether/ {print toupper($2)}')
    local vendor
    vendor=$(get_oui "$new_mac")

    echo "[*] Using provided MAC address: $new_mac ($vendor)"
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
hardware_check || { echo -e "${RED}[!] Hardware check failed. Exiting.${RESET}"; exit 1; }
channel_check || { echo -e "${RED}[!] Channel check failed. Exiting.${RESET}"; exit 1; }
install_dependencies
check_oui

sudo systemctl stop NetworkManager

echo "[*] Setting $WIFI_INTERFACE to AP mode..."
sudo ip link set $WIFI_INTERFACE down
sudo ip addr flush dev $WIFI_INTERFACE
set_ap_mac
sudo iw dev $WIFI_INTERFACE set type ap 2>/dev/null
sudo ip addr add $AP_IP/24 dev $WIFI_INTERFACE
sudo ip link set $WIFI_INTERFACE up

# --- DETERMINE BAND & CAPABILITIES BASED ON CHANNEL ---
if (( CHANNEL >= 1 && CHANNEL <= 14 )); then
    HW_MODE="g"
    IEEE80211N="ieee80211n=1"
    IEEE80211AC=""
    HT_CAPAB="[HT40+]"
    VHT_CAPAB=""
elif (( CHANNEL >= 36 && CHANNEL <= 165 )); then
    HW_MODE="a"
    IEEE80211N="ieee80211n=1"
    IEEE80211AC="ieee80211ac=1"
    HT_CAPAB="[HT40+]"
    VHT_CAPAB="[VHT80]"
else
    echo -e "${RED}Invalid channel number: $CHANNEL${RESET}"
    exit 1
fi


# --- HOSTAPD CONFIG ---
HOSTAPD_CONF="/tmp/hostapd.conf"

# Calculate center frequency based on channel
get_center_freq() {
    local channel=$1
    case $channel in
        36|40|44|48) echo "42" ;;
        149|153|157|161) echo "155" ;;
        165) echo "155" ;;
        *) echo "$((channel + 2))" ;;
    esac
}

CENTER_FREQ=$(get_center_freq $CHANNEL)

cat <<EOF > $HOSTAPD_CONF
interface=$WIFI_INTERFACE
driver=nl80211
ssid=$SSID
hw_mode=$HW_MODE
channel=$CHANNEL
ignore_broadcast_ssid=0
$IEEE80211N
$IEEE80211AC
ht_capab=$HT_CAPAB
vht_capab=$VHT_CAPAB
country_code=$COUNTRY
ieee80211d=1
ieee80211h=1
auth_algs=1  # open wifi
wmm_enabled=1
EOF

# Only add VHT settings for 5GHz
if (( CHANNEL >= 36 && CHANNEL <= 165 )); then
    echo "vht_oper_chwidth=1" >> $HOSTAPD_CONF
    echo "vht_oper_centr_freq_seg0_idx=$CENTER_FREQ" >> $HOSTAPD_CONF
fi

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

echo -e "${GREEN}[✓] AP ${ORANGE}'$SSID'${RESET} ${GREEN}started on Channel ${ORANGE}'$CHANNEL'.${RESET}"
echo -e "[*] Waiting for clients to connect:\n\n"

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

            echo -e "${GREEN}${MSG}${RESET}"
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

            echo -e "${RED}${MSG}${RESET}"
            echo "$MSG" >> "$LOG_FILE"
            #release_ip "$MAC"
            unset CLIENTS[$MAC]
        fi
    done

    sleep 0.5
done
