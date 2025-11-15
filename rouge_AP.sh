#!/bin/bash
# Version 1.6 16/11/25 02:50

UN=${SUDO_USER:-$(whoami)}

# --- CONFIG ---
SSID="OOOpen"
CHANNEL=""    # Supports 2.4GHz and 5GHz. You can leave empty too.
AP_MAC=""      # You can set any MAC you want (spoofing existing AP). You can leave empty too.
COUNTRY="TH"   # set your country here its important for RESTRICTED and DFS channels. You can leave empty too.
                

# Check US channels: 42,169,34,4,
# TH: 38,46,

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



# --- COUNTRY CHECK ---
country_check() {
    # Get current regulatory domain
    local current_reg
    current_reg=$(iw reg get 2>/dev/null | grep "country" | head -1 | awk '{print $2}' | sed 's/://')
    echo -e "[*] Current Country: ${current_reg:-Not set}"

    # If COUNTRY is empty, set it based on current_reg
    if [[ -z "$COUNTRY" ]]; then
        if [[ "$current_reg" == "00" ]]; then
            echo "[*] Regulatory domain is 00, setting country to 'US'."
            COUNTRY="US"
        elif [[ -n "$current_reg" ]]; then
            COUNTRY="$current_reg"
        else
            echo "[*] No country specified and cannot detect current, setting to 'US'."
            COUNTRY="US"
        fi
    fi

    # If COUNTRY is explicitly set to "00", change it to US
    if [[ "$COUNTRY" == "00" ]]; then
        echo "[!] hostapd won't accept region '00'. changing to 'US'."
        COUNTRY="US"
    fi

    # If COUNTRY has value and it's different from current_reg, then set it
    if [[ "$current_reg" != "$COUNTRY" ]]; then
        echo -e "[*] Changing country to $COUNTRY..."
        sudo iw reg set "$COUNTRY" > /dev/null 2>&1
    fi
}


# --- CHANNEL CHECK ---
channel_check() {
    # Get allowed and DFS channels from regulatory domain
    local reg_info=$(iw reg get)
    
    local channel_info=$(echo "$reg_info" | awk '
    function freq_to_channel(freq, band) {
        # 2.4 GHz
        if (band == 1) {
            if (freq >= 2412 && freq <= 2472) return int((freq - 2407)/5)
            if (freq == 2484) return 14
        }
        # 5 GHz explicit mapping
        if (band == 2) {  
            if (freq == 4910) return 1;   if (freq == 4915) return 2;   if (freq == 4920) return 3
            if (freq == 4925) return 4;   if (freq == 4930) return 5;   if (freq == 4935) return 6
            if (freq == 4940) return 7;   if (freq == 4945) return 8;   if (freq == 4950) return 9
            if (freq == 4955) return 10;  if (freq == 4960) return 11;  if (freq == 4965) return 12
            if (freq == 4970) return 13;  if (freq == 4975) return 14;  if (freq == 4980) return 15
            if (freq == 4985) return 16;  if (freq == 4990) return 17;  if (freq == 5170) return 34
            if (freq == 5180) return 36;  if (freq == 5190) return 38;  if (freq == 5200) return 40
            if (freq == 5210) return 42;  if (freq == 5220) return 44;  if (freq == 5230) return 46
            if (freq == 5240) return 48;  if (freq == 5260) return 52;  if (freq == 5280) return 56
            if (freq == 5300) return 60;  if (freq == 5320) return 64;  if (freq == 5340) return 68
            if (freq == 5480) return 96;  if (freq == 5500) return 100; if (freq == 5520) return 104
            if (freq == 5540) return 108; if (freq == 5560) return 112; if (freq == 5580) return 116
            if (freq == 5600) return 120; if (freq == 5620) return 124; if (freq == 5640) return 128
            if (freq == 5660) return 132; if (freq == 5680) return 136; if (freq == 5700) return 140
            if (freq == 5720) return 144; if (freq == 5745) return 149; if (freq == 5765) return 153
            if (freq == 5785) return 157; if (freq == 5805) return 161; if (freq == 5825) return 165
            if (freq == 5845) return 169; if (freq == 5865) return 173 
        }
        return ""
    }
    BEGIN { allowed = ""; dfs = "" }
    /\([0-9]+ - [0-9]+/ {
        match($0, /\(([0-9]+) - ([0-9]+)/, m)
        start = m[1]; end = m[2]
        rest = $0; sub(/^[^)]*\) *,? */, "", rest); gsub(/^ +| +$/, "", rest)
        split(rest, restr_array, ",")
        restrictions = ""
        for (i in restr_array) {
            r = restr_array[i]
            gsub(/^ +| +$/, "", r); gsub(/^\(|\)$/, "", r)
            if (r !~ /^N\/A/ && r !~ /0 ms/ && r !~ /^[0-9]+$/) {
                if (restrictions == "") restrictions = r
                else restrictions = restrictions " - " r
            }
        }
        if (start >= 2400 && end <= 2500) { band = 1; step=5 }
        else if (start >= 4910 && end <= 5865) { band = 2; step=5 }
        else next
        for (f = start; f <= end; f += step) {
            ch = freq_to_channel(f, band)
            if (ch == "") continue
            if ((band == 1 || band == 2) && restrictions !~ /DFS/) {
                if (allowed == "") allowed = ch; else allowed = allowed "," ch
            }
            if ((band == 1 || band == 2) && restrictions ~ /DFS/) {
                if (dfs == "") dfs = ch; else dfs = dfs "," ch
            }
        }
    }
    END { print allowed "|" dfs }
    ')
    
    # Split the result into allowed_channels and dfs_channels
    allowed_channels=$(echo "$channel_info" | cut -d'|' -f1)
    dfs_channels=$(echo "$channel_info" | cut -d'|' -f2)

    # Get hardware disabled channels - FIXED VERSION
    local disabled_channels=$(iw list 2>/dev/null | awk '
    BEGIN { disabled_24 = ""; disabled_5 = "" }
    /MHz.*\[.*\].*disabled/ {
        # Extract channel number from brackets
        if (match($0, /\[([0-9]+)\].*disabled/)) {
            channel = substr($0, RSTART+1, RLENGTH-1)
            channel = substr(channel, 1, index(channel, "]")-1)
            
            # Determine band based on frequency
            if ($0 ~ /24[0-9][0-9]/) {
                if (disabled_24 == "") disabled_24 = channel
                else disabled_24 = disabled_24 "," channel
            }
            else if ($0 ~ /[0-9]{4}\.[0-9]/ && $0 !~ /24[0-9][0-9]/) {
                if (disabled_5 == "") disabled_5 = channel
                else disabled_5 = disabled_5 "," channel
            }
        }
    }
    END { print disabled_24 "|" disabled_5 }
    ')
    
    local disabled_24=$(echo "$disabled_channels" | cut -d'|' -f1)
    local disabled_5=$(echo "$disabled_channels" | cut -d'|' -f2)

    # Debug: Show what channels we found
    echo -e "${GREEN}[✓] Allowed channels:${RESET} $allowed_channels"
    echo -e "${RED}[!] DFS channels:${RESET} $dfs_channels"
    
    # Show disabled channels 
    if [[ -n "$disabled_24" && -n "$disabled_5" ]]; then
        echo -e "${RED}[!] Disabled Hardware channels:${RESET} 2.4GHz - $disabled_24. 5GHz - $disabled_5"
    elif [[ -n "$disabled_24" ]]; then
        echo -e "${RED}[!] Disabled Hardware channels:${RESET} 2.4GHz - $disabled_24"
    elif [[ -n "$disabled_5" ]]; then
        echo -e "${RED}[!] Disabled Hardware channels:${RESET} 5GHz - $disabled_5"
    fi
    
    
    
    
    
    # --- Manual channel selection - don't change, just validate ---
    if [[ -n "$CHANNEL" ]]; then
        echo "[*] Specified channel: $CHANNEL"
        
        # Check if manually selected channel is hardware disabled
        if [[ -n "$disabled_24" && ",$disabled_24," == *",$CHANNEL,"* ]] || 
           [[ -n "$disabled_5" && ",$disabled_5," == *",$CHANNEL,"* ]]; then
            echo -e "${RED}[!] ERROR: Channel $CHANNEL is HARDWARE DISABLED on this adapterfor $COUNTRY!${RESET}"
            echo "           You can change country if you want to use this channel."
            cleanup
            exit 1
        fi

        # Check if manually selected channel is DFS
        if echo "$dfs_channels" | grep -qw "$CHANNEL"; then
            echo -e "${RED}[!] WARNING: Channel $CHANNEL is DFS (may not work in AP mode)${RESET}"
            # Don't return error, just warn
        fi

        #echo -e "${GREEN}[✓] Using manually specified channel: $CHANNEL${RESET}"
        
    # --- Randomized channel selection - filter out disabled channels ---
    else
        echo "[*] No channel specified, randomizing channel..."
        
        # Create list of available channels (allowed AND not disabled)
        local available_channels=""
        for ch in $(echo "$allowed_channels" | tr ',' ' '); do
            # Skip if channel is hardware disabled
            if [[ -n "$disabled_24" && ",$disabled_24," == *",$ch,"* ]]; then
                continue
            fi
            if [[ -n "$disabled_5" && ",$disabled_5," == *",$ch,"* ]]; then
                continue
            fi
            available_channels="$available_channels$ch,"
        done
        
        available_channels=$(echo "$available_channels" | sed 's/,$//')
        
        if [[ -z "$available_channels" ]]; then
            echo -e "${RED}[!] ERROR: No available channels after filtering hardware disabled ones!${RESET}"
            return 1
        fi
        
        # Pick random channel from available ones
        CHANNEL=$(echo "$available_channels" | tr ',' '\n' | shuf -n1)
        echo -e "${GREEN}[✓] Randomized channel selected: $CHANNEL${RESET}"
    fi
    
    return 0
}


# --- CLEANUP FUNCTION ---
cleanup() {
    echo -e "\n[*] Stopping AP..."
    sudo pkill hostapd
    sudo rm -f /tmp/hostapd.conf
    sudo pkill dnsmasq
    sudo rm -f /var/lib/misc/dnsmasq.leases
    sudo iptables -t nat -D POSTROUTING -o $LAN_INTERFACE -j MASQUERADE 2>/dev/null
    sudo iptables -D FORWARD -i $LAN_INTERFACE -o $WIFI_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    sudo iptables -D FORWARD -i $WIFI_INTERFACE -o $LAN_INTERFACE -j ACCEPT 2>/dev/null
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
country_check
channel_check
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
    #HT_CAPAB="[HT40+]"
    #VHT_CAPAB=""
elif (( CHANNEL >= 36 && CHANNEL <= 169 )); then
    HW_MODE="a"
    IEEE80211N="ieee80211n=1"
    IEEE80211AC="ieee80211ac=1"
    HT_CAPAB="[HT40+]"
    VHT_CAPAB="[VHT80]"
else
    echo -e "${RED}[!] Invalid channel: $CHANNEL in your region: $COUNTRY.${RESET}"
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
ssid=$SSID
channel=$CHANNEL
country_code=$COUNTRY
auth_algs=1   # open wifi
driver=nl80211
hw_mode=$HW_MODE
$IEEE80211N
$IEEE80211AC
ht_capab=$HT_CAPAB
vht_capab=$VHT_CAPAB
ieee80211d=1 # if you set 0 - Radar detection may be bypassed (illegal in some regions) may still be blocked on the driver level.
ieee80211h=1 # if you set 0 - AP works on DFS channels that require radar detection (illegal in MOST regions) may still be blocked on the driver level.  
wmm_enabled=1
ignore_broadcast_ssid=0
EOF

# Only add VHT settings for 5GHz
if (( CHANNEL >= 36 && CHANNEL <= 165 )); then
    echo "vht_oper_chwidth=1" >> $HOSTAPD_CONF
    echo "vht_oper_centr_freq_seg0_idx=$CENTER_FREQ" >> $HOSTAPD_CONF
fi


# --- Start hostapd ---
sudo hostapd $HOSTAPD_CONF > /tmp/hostapd.log 2>&1 & 
HAPD_PID=$!

echo "[*] Starting hostapd..."
timeout=15   # max seconds to wait
elapsed=0
while [ $elapsed -lt $timeout ]; do
    if grep -q "AP-ENABLED" /tmp/hostapd.log; then
        break
    fi
    if grep -qi -E "AP-DISABLED|error|invalid" /tmp/hostapd.log; then
        echo -e "${RED}[!] Hostapd failed to start.${RESET}"
        echo -e "${RED}--- Hostapd log ---${RESET}"
        #grep -i -E "AP-DISABLED|Could not select|Hardware does not support|Invalid|error|Failed" /tmp/hostapd.log
        awk '{print "\t"$0}' /tmp/hostapd.log
        kill $HAPD_PID 2>/dev/null
        cleanup
        exit 1
    fi
    sleep 1
    ((elapsed++))
done

# Final check after waiting
if ! grep -q "AP-ENABLED" /tmp/hostapd.log; then
    echo -e "${RED}[!] Hostapd did not start within $timeout seconds. Check /tmp/hostapd.log${RESET}"
    cleanup
    exit 1
fi


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

echo -e "\n${GREEN}[✓] AP ${ORANGE}'$SSID'${RESET} ${GREEN}started on Channel ${ORANGE}'$CHANNEL'.${RESET}"
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
