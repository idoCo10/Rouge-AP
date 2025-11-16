#!/bin/bash
# Version 2.0 17/11/25 02:00


UN=${SUDO_USER:-$(whoami)}

# --- CONFIG ---
SSID=""    # Default is "Open WiFi" if you leave SSID empty.
CHANNEL=""    # Supports 2.4GHz and 5GHz. You can leave empty and the script will randomize channel.
AP_MAC=""      # You can set any MAC you want (spoofing existing AP). You can leave empty too.
COUNTRY=""   # set your country here. You can leave empty, default is US. be aware of regulations.
                



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
MAGENTA='\033[0;35m'
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
    #else
        #echo -e "${GREEN}[✓] All dependencies already installed.${RESET}"
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
    echo -e "[*] Current Country: ${current_reg:-Not set}."

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
    local iw_output
    iw_output=$(iw list 2>/dev/null)

    # Initialize arrays
    declare -A allowed_24 allowed_5 allowed_6
    declare -A dfs_24 dfs_5 dfs_6
    declare -A disabled_24 disabled_5 disabled_6
    declare -A noir_24 noir_5 noir_6

    # Parse iw list output
    while IFS= read -r line; do
        # Detect band
        if [[ "$line" =~ ^[[:space:]]*Band[[:space:]]+([0-9]+): ]]; then
            case "${BASH_REMATCH[1]}" in
                1) current_band="24" ;;
                2) current_band="5" ;;
                4) current_band="6" ;;
                *) current_band="" ;;
            esac
            continue
        fi

        # Skip if no band
        [[ -z "$current_band" ]] && continue

        # Detect channel lines: * MHz [num] (restrictions)
        if [[ "$line" =~ \[*[[:space:]]*([0-9]+)[[:space:]]*MHz[[:space:]]*\[([0-9]+)\](.*) ]]; then
            local channel="${BASH_REMATCH[2]}"
            local rest="${BASH_REMATCH[3]}"

            local type="allowed"
            [[ "$rest" =~ disabled ]] && type="disabled"
            [[ "$rest" =~ "radar detection" ]] && type="dfs"
            [[ "$rest" =~ "no IR" ]] && type="noir"

            # Sometimes both DFS and no IR exist
            [[ "$rest" =~ "radar detection" ]] && [[ "$rest" =~ "no IR" ]] && type="dfs_noir"

            case "$current_band:$type" in
                "24:allowed") allowed_24["$channel"]=1 ;;
                "5:allowed") allowed_5["$channel"]=1 ;;
                "6:allowed") allowed_6["$channel"]=1 ;;
                "24:dfs") dfs_24["$channel"]=1 ;;
                "5:dfs") dfs_5["$channel"]=1 ;;
                "6:dfs") dfs_6["$channel"]=1 ;;
                "24:disabled") disabled_24["$channel"]=1 ;;
                "5:disabled") disabled_5["$channel"]=1 ;;
                "6:disabled") disabled_6["$channel"]=1 ;;
                "24:noir") noir_24["$channel"]=1 ;;
                "5:noir") noir_5["$channel"]=1 ;;
                "6:noir") noir_6["$channel"]=1 ;;
                "24:dfs_noir")
                    dfs_24["$channel"]=1
                    noir_24["$channel"]=1
                    ;;
                "5:dfs_noir")
                    dfs_5["$channel"]=1
                    noir_5["$channel"]=1
                    ;;
                "6:dfs_noir")
                    dfs_6["$channel"]=1
                    noir_6["$channel"]=1
                    ;;
            esac
        fi
    done <<< "$iw_output"

	# Helper function to format channel lists numerically
	format_channels() {
	    local -n channels=$1
	    if [ ${#channels[@]} -eq 0 ]; then
		echo "(none)"
		return
	    fi
	    # Extract keys and sort numerically
	    local sorted=($(printf '%s\n' "${!channels[@]}" | sort -n))
	    printf '%s' "$(IFS=,; echo "${sorted[*]}")"
	}

    # Display results
    echo -e "[*] Channel information in $COUNTRY:"
    
    # Allowed channels
    echo -e "    ${GREEN}[✓] Allowed channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels allowed_24)"
    echo -e "        5GHz:   $(format_channels allowed_5)"
    echo -e "        6GHz:   $(format_channels allowed_6)"

    # DFS channels
    echo -e "    ${YELLOW}[!] DFS (radar detection) channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels dfs_24)"
    echo -e "        5GHz:   $(format_channels dfs_5)"
    echo -e "        6GHz:   $(format_channels dfs_6)"

    # Disabled channels
    echo -e "    ${RED}[!] Disabled channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels disabled_24)"
    echo -e "        5GHz:   $(format_channels disabled_5)"
    echo -e "        6GHz:   $(format_channels disabled_6)"

    # No IR channels
    echo -e "    ${BLUE}[!] No IR channels:${RESET}"
    echo -e "        2.4GHz: $(format_channels noir_24)"
    echo -e "        5GHz:   $(format_channels noir_5)"
    echo -e "        6GHz:   $(format_channels noir_6)"

    

# --- Manual channel selection ---
if [[ -n "$CHANNEL" ]]; then
    echo -e "\n[*] Specified channel: $CHANNEL"

    # Check if manually selected channel is hardware disabled
    if [[ -n "${disabled_24[$CHANNEL]}" || -n "${disabled_5[$CHANNEL]}" ]]; then
        echo -e "${RED}[!] ERROR: Channel $CHANNEL is DISABLED for $COUNTRY!${RESET}"
        cleanup
    fi

    # --- Check DFS restrictions ---
    if echo "$dfs_channels" | grep -qw "$CHANNEL"; then
        echo -e "${RED}[!] ERROR: Channel $CHANNEL has DFS (radar detection) restriction in $COUNTRY!${RESET}"
        cleanup
    fi
    
    # --- Check No IR restrictions ---
    if [[ -n "${noir_24[$CHANNEL]}" || -n "${noir_5[$CHANNEL]}" ]]; then
        echo -e "${RED}[!] ERROR: Channel $CHANNEL has No IR (cannot initiate AP) restriction in $COUNTRY!${RESET}"
        cleanup
    fi

    # Check if channel is in allowed 2.4GHz or 5GHz
    if [[ -z "${allowed_24[$CHANNEL]}" && -z "${allowed_5[$CHANNEL]}" ]]; then
        echo -e "${RED}[!] ERROR: Channel $CHANNEL is not in the allowed 2.4GHz or 5GHz channels for $COUNTRY!${RESET}"
        cleanup
    fi
    
    echo -e "${GREEN}[✓] Channel $CHANNEL is allowed.${RESET}\n"

        
# --- Randomized channel selection ---
else
        echo -e "\n[*] No channel specified, randomizing channel..."
        
	# Merge allowed_24 and allowed_5 into available_channels
	available_channels=("${!allowed_24[@]}" "${!allowed_5[@]}")

	# Sort numerically (optional)
	available_channels=($(printf '%s\n' "${available_channels[@]}" | sort -n))
	
	#echo -e "\n\nChannels Pool: ${available_channels[*]}\n\n"

	# Pick a random channel
	CHANNEL="${available_channels[RANDOM % ${#available_channels[@]}]}"
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
    echo -e "${GREEN}[✓] Cleanup complete. Wi-Fi interface restored to normal mode.${RESET}"
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
        [[ ! -f "$OUI_FILE" ]] && { echo -e "${RED}Failed to download OUI vendor file.${RESET}"; }
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




# --- HOSTAPD CONFIG ---
HOSTAPD_CONF="/tmp/hostapd.conf"

# Calculate center frequency based on channel
get_center_freq() {
    local channel=$1
    case $channel in
        # UNII-1 Block 36-48 (Center 42)
        36|40|44|48) echo "42" ;;
        # UNII-2a Block 52-64 (Center 58) 
        52|56|60|64) echo "58" ;;
        # UNII-2c Block 100-112 (Center 106)
        100|104|108|112) echo "106" ;;
        # UNII-2c Block 116-128 (Center 122)
        116|120|124|128) echo "122" ;;
        # UNII-2c Block 132-144 (Center 138)
        132|136|140|144) echo "138" ;;
        # UNII-3 Block 149-161 (Center 155)
        149|153|157|161) echo "155" ;;
        # 165-169 are 20MHz only - no center frequency needed
        165|169) echo "" ;;
        # 2.4GHz channels don't use center frequency concept for VHT
        *) echo "$channel" ;;
    esac
}

CENTER_FREQ=$(get_center_freq $CHANNEL)

# --- DETERMINE BAND & CAPABILITIES BASED ON CHANNEL ---
if (( CHANNEL >= 1 && CHANNEL <= 14 )); then
    # 2.4GHz
    HW_MODE="g"
    IEEE80211N="ieee80211n=1"
    HT_CAPAB="[HT20]"

elif (( CHANNEL >= 36 && CHANNEL <= 161 )); then
    # 5GHz with VHT support (channels 36-161)
    HW_MODE="a"
    IEEE80211N="ieee80211n=1"
    IEEE80211AC="ieee80211ac=1"
    HT_CAPAB="[HT40+]"
    VHT_CAPAB="[SHORT-GI-80][SU-BEAMFORMEE][VHT80]"
    VHT_EXTRA="vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=$CENTER_FREQ"
    
elif (( CHANNEL >= 165 && CHANNEL <= 177 )); then
    # 5GHz without VHT (20MHz only)
    HW_MODE="a"
    IEEE80211N="ieee80211n=1"
    HT_CAPAB="[HT20]"
    
else
    echo -e "${RED}[!] Invalid channel: $CHANNEL in your region: $COUNTRY.${RESET}"
    cleanup
fi

SSID=${SSID:-Open WiFi} # use "Open WiFi" if $SSID is empty

# Create hostapd configuration
cat <<EOF > $HOSTAPD_CONF
interface=$WIFI_INTERFACE
ssid=$SSID 
channel=$CHANNEL
country_code=$COUNTRY
auth_algs=1
driver=nl80211
hw_mode=$HW_MODE
$IEEE80211N
$IEEE80211AC
EOF

# Only add these if they have values
[[ -n "$HT_CAPAB" ]] && echo "ht_capab=$HT_CAPAB" >> $HOSTAPD_CONF
[[ -n "$VHT_CAPAB" ]] && echo "vht_capab=$VHT_CAPAB" >> $HOSTAPD_CONF
[[ -n "$VHT_EXTRA" ]] && echo "$VHT_EXTRA" >> $HOSTAPD_CONF

cat <<EOF >> $HOSTAPD_CONF
ieee80211d=1
ieee80211h=1
wmm_enabled=1
ignore_broadcast_ssid=0
EOF


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
        awk '{print "\t"$0}' /tmp/hostapd.log
        kill $HAPD_PID 2>/dev/null
        cleanup
    fi
    sleep 1
    ((elapsed++))
done

# Final check after waiting
if ! grep -q "AP-ENABLED" /tmp/hostapd.log; then
    echo -e "${RED}[!] Hostapd did not start within $timeout seconds. Check /tmp/hostapd.log${RESET}"
    cleanup
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
