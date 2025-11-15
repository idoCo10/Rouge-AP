#!/usr/bin/env bash


current_reg=$(iw reg get 2>/dev/null | grep "country" | head -1 | awk '{print $2}' | sed 's/://')
echo -e "Current Country: ${current_reg:-Not set}\n"
echo -e "Available Channels:"
iw reg get | awk '

function freq_to_channel(freq, band) {
    # 900 MHz band
    if (band == 0) {
        # 900MHz channels are typically 1:1 mapping in some systems
        # For display purposes, we can use the frequency directly or calculate offset
        if (freq >= 902 && freq <= 928) return int((freq - 902) / 2) + 1
    }
    
    # 2.4 GHz
    if (band == 1) {
        if (freq >= 2412 && freq <= 2472) return int((freq - 2407)/5)
        if (freq == 2484) return 14
    }

    # 5 GHz explicit mapping - expanded for US and other regions
    if (band == 2) {  
        # Japan specific
        if (freq == 4910) return 1
        if (freq == 4915) return 2
        if (freq == 4920) return 3
        if (freq == 4925) return 4
        if (freq == 4930) return 5
        if (freq == 4935) return 6
        if (freq == 4940) return 7
        if (freq == 4945) return 8
        if (freq == 4950) return 9
        if (freq == 4955) return 10
        if (freq == 4960) return 11
        if (freq == 4965) return 12
        if (freq == 4970) return 13
        if (freq == 4975) return 14
        if (freq == 4980) return 15
        if (freq == 4985) return 16
        if (freq == 4990) return 17
        
        # Standard UNII-1, UNII-2, UNII-2e, UNII-3
        if (freq == 5170) return 34
        if (freq == 5180) return 36
        if (freq == 5190) return 38         
        if (freq == 5200) return 40
        if (freq == 5210) return 42
        if (freq == 5220) return 44
        if (freq == 5230) return 46
        if (freq == 5240) return 48
        if (freq == 5250) return 50
        if (freq == 5260) return 52
        if (freq == 5270) return 54
        if (freq == 5280) return 56
        if (freq == 5290) return 58
        if (freq == 5300) return 60
        if (freq == 5310) return 62
        if (freq == 5320) return 64
        if (freq == 5340) return 68
        if (freq == 5480) return 96
        if (freq == 5500) return 100
        if (freq == 5520) return 104
        if (freq == 5540) return 108
        if (freq == 5560) return 112
        if (freq == 5580) return 116
        if (freq == 5600) return 120
        if (freq == 5620) return 124
        if (freq == 5640) return 128
        if (freq == 5660) return 132
        if (freq == 5680) return 136
        if (freq == 5700) return 140
        if (freq == 5720) return 144
        if (freq == 5745) return 149
        if (freq == 5765) return 153
        if (freq == 5785) return 157
        if (freq == 5805) return 161
        if (freq == 5825) return 165
        if (freq == 5845) return 169
        if (freq == 5865) return 173
        if (freq == 5885) return 177  # Additional US channels
        if (freq == 5905) return 181  # Additional US channels
    }

    # 6 GHz Wi-Fi channels (US/standard) 20MHz spacing
    if (band == 3) {
        if (freq == 5955) return 1
        if (freq == 5975) return 5
        if (freq == 5995) return 9
        if (freq == 6015) return 13
        if (freq == 6035) return 17
        if (freq == 6055) return 21
        if (freq == 6075) return 25
        if (freq == 6095) return 29
        if (freq == 6115) return 33
        if (freq == 6135) return 37
        if (freq == 6155) return 41
        if (freq == 6175) return 45
        if (freq == 6195) return 49
        if (freq == 6215) return 53
        if (freq == 6235) return 57
        if (freq == 6255) return 61
        if (freq == 6275) return 65
        if (freq == 6295) return 69
        if (freq == 6315) return 73
        if (freq == 6335) return 77
        if (freq == 6355) return 81
        if (freq == 6375) return 85
        if (freq == 6395) return 89
        if (freq == 6415) return 93
        if (freq == 6435) return 97
        if (freq == 6455) return 101
        if (freq == 6475) return 105
        if (freq == 6495) return 109
        if (freq == 6515) return 113
        if (freq == 6535) return 117
        if (freq == 6555) return 121
        if (freq == 6575) return 125
        if (freq == 6595) return 129
        if (freq == 6615) return 133
        if (freq == 6635) return 137
        if (freq == 6655) return 141
        if (freq == 6675) return 145
        if (freq == 6695) return 149
        if (freq == 6715) return 153
        if (freq == 6735) return 157
        if (freq == 6755) return 161
        if (freq == 6775) return 165
        if (freq == 6795) return 169
        if (freq == 6815) return 173
        if (freq == 6835) return 177
        if (freq == 6855) return 181
        if (freq == 6875) return 185
        if (freq == 6895) return 189
        if (freq == 6915) return 193
        if (freq == 6935) return 197
        if (freq == 6955) return 201
        if (freq == 6975) return 205
        if (freq == 6995) return 209
        if (freq == 7015) return 213
        if (freq == 7035) return 217
        if (freq == 7055) return 221
        if (freq == 7075) return 225
        if (freq == 7095) return 229
        if (freq == 7115) return 233
    }

    # 60 GHz (802.11ad/ay)
    if (band == 4) {
        if (freq == 58320) return 1
        if (freq == 60480) return 2
        if (freq == 62640) return 3
        if (freq == 64800) return 4
    }

    return ""
}


/\([0-9]+ - [0-9]+/ {
    # extract start and end frequency
    match($0, /\(([0-9]+) - ([0-9]+)/, m)
    start = m[1]; end = m[2]

    # extract restrictions dynamically (ignore N/A, 0 ms, and power values)
    rest = $0
    sub(/^[^)]*\) *,? */, "", rest)
    gsub(/^ +| +$/, "", rest)
    split(rest, restr_array, ",")
    restrictions = ""
    for (i in restr_array) {
        r = restr_array[i]
        gsub(/^ +| +$/, "", r)       # trim spaces
        gsub(/^\(|\)$/, "", r)       # remove any leading/trailing parentheses
        
        # Skip N/A, 0 ms, and numeric power values (like 20, 23, 10, etc.)
        if (r !~ /^N\/A/ && r !~ /0 ms/ && r !~ /^[0-9]+$/) {
            if (restrictions == "") restrictions = r
            else restrictions = restrictions " - " r
        }
    }

    # determine band and label - EXPANDED RANGES
    if (start >= 902 && end <= 928) { band = 0; bandtxt="(900MHz)"; step=2 }
    else if (start >= 2400 && end <= 2500) { band = 1; bandtxt="(2.4GHz)"; step=5 }
    else if ((start >= 4910 && end <= 5895) || (start >= 5150 && end <= 5895)) { band = 2; bandtxt="(5GHz)"; step=5 }
    else if (start >= 5925 && end <= 7125) { band = 3; bandtxt="(6GHz)"; step=1 }
    else if (start >= 57000) { band = 4; bandtxt="(60GHz)"; step=1 }
    else next

    # print all channels in range
    for (f = start; f <= end; f += step) {
        ch = freq_to_channel(f, band)
        if (ch == "") continue
        if (restrictions != "") print ch " " bandtxt " - " restrictions
        else print ch " " bandtxt
    }
}
'
