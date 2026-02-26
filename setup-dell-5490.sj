#!/bin/bash
#===============================================================================
# Dell Latitude 5490 Ubuntu 24.04 LTS Setup Script
#
# Configures a fresh Ubuntu 24.04 installation with fixes for:
#   - Display wake lockup (i915 DC5/DC6 GPU power state bug)
#   - Hibernate on lid close
#   - GDM startup race condition
#   - Desktop environment customization
#
# Target hardware:
#   Dell Latitude 5490, Intel i5-8350U, Intel UHD 620 (Kaby Lake)
#   Tested on Ubuntu 24.04.4 LTS with kernel 6.17.0-14-generic (HWE)
#
# Prerequisites:
#   - Fresh Ubuntu Desktop 24.04 LTS installation
#   - Secure Boot disabled in BIOS (required for hibernate)
#   - Run as root: sudo bash setup-dell-5490.sh
#
#-------------------------------------------------------------------------------
# HARDWARE-SPECIFIC ASSUMPTIONS
#
# This script makes several assumptions that are specific to the target
# hardware and software configuration. Adapting it to other systems requires
# reviewing each of the following:
#
# 1. BACKLIGHT PATH
#    Hardcoded to /sys/class/backlight/intel_backlight
#    This is specific to Intel integrated graphics. AMD or NVIDIA systems
#    will have a different path (e.g., /sys/class/backlight/amdgpu_bl0).
#    Verify with: ls /sys/class/backlight/
#
# 2. PCI DEVICE PATH
#    The GPU PCI address 0000:00:02.0 is hardcoded in the hibernate drop-in
#    (/etc/systemd/system/systemd-hibernate.service.d/gpu-fix.conf) and the
#    udev rule (80-gpu-no-runtime-pm.rules). This is the standard address
#    for Intel integrated graphics on virtually all Intel systems. The udev
#    rule additionally matches by vendor ID (0x8086) and device class
#    (0x030000) for safety. Verify with: lspci -s 00:02.0
#
# 3. XAUTHORITY PATH
#    Smart-blank assumes GDM as the display manager, which stores the
#    Xauthority file at /run/user/UID/gdm/Xauthority. Other display
#    managers (LightDM, SDDM) use ~/.Xauthority. The script checks both
#    paths but tries the GDM path first.
#
# 4. DISPLAY SERVER
#    Assumes X11 (Wayland is explicitly disabled). Smart-blank depends on
#    xset, xprintidle, and XAUTHORITY — none of which exist under Wayland.
#    The DISPLAY number is auto-detected from the gnome-shell process
#    (typically :1 on Ubuntu 24.04 with GDM, not :0).
#
# 5. i915 DRIVER BUGS (Kaby Lake + kernel 6.17)
#    - PSR (Panel Self Refresh) causes display flickering — disabled via
#      modprobe option.
#    - DPMS triggers DC5/DC6 GPU power states that lock up the display —
#      bypassed entirely by smart-blank (direct sysfs backlight control).
#    - GPU runtime suspend causes i915 FIFO underrun during hibernate —
#      fixed by forcing GPU out of runtime suspend immediately before
#      hibernate via a systemd-hibernate drop-in.
#    - power-profiles-daemon overrides the GPU runtime PM udev rule after
#      boot, setting it back to 'auto'. This is acceptable because
#      smart-blank uses sysfs (not DPMS), and the hibernate drop-in
#      handles the hibernate case specifically.
#
# 6. GDM RACE CONDITION
#    On this hardware, GDM occasionally starts before the GPU is ready,
#    resulting in a blank screen. The gdm-fix.service retries GDM startup
#    up to 3 times with 15-second intervals.
#
# 7. UPOWER (GNOME 46)
#    Critical battery settings (CriticalPowerAction, PercentageAction) are
#    configured via /etc/UPower/UPower.conf. The gsettings keys for these
#    do not exist in GNOME 46 — earlier GNOME versions may differ.
#
# 8. SWAP SIZING
#    Swap is auto-sized to RAM + 1GB (rounded up) for hibernate support.
#    Hibernate requires swap >= RAM to store the full memory image. The
#    swap file is created at /swap.img on the root filesystem.
#
# 9. FUSE MOUNTS
#    /run/user/UID/ contains FUSE mounts (gvfs, doc) that block
#    non-interactive processes. The smart-blank script avoids using 'find'
#    on this directory for this reason.
#
#===============================================================================

set -uo pipefail

VERSION="1.0.0"

case "${1:-}" in
    -v|--version) echo "setup-dell-5490 $VERSION"; exit 0 ;;
    -h|--help)
        echo "Usage: sudo bash setup-dell-5490.sh [OPTIONS]"
        echo ""
        echo "Interactive setup script for Dell Latitude 5490 on Ubuntu 24.04."
        echo ""
        echo "Options:"
        echo "  -v, --version    Show version number"
        echo "  -h, --help       Show this help message"
        exit 0
        ;;
esac

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
USERNAME="${SUDO_USER:-$(logname)}"
SWAP_SIZE="$(( $(awk '/MemTotal/ {print int($2 / 1024 / 1024) + 1}' /proc/meminfo) ))G"
SCREEN_IDLE_TIMEOUT=300                                # Smart-blank idle timeout in seconds
BACKLIGHT_PATH="/sys/class/backlight/intel_backlight"   # Intel iGPU sysfs backlight path

#-------------------------------------------------------------------------------
# Colors
#-------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

#-------------------------------------------------------------------------------
# Section ordering — grouped by category, dependency order within each group
#
#   A. DISPLAY (GPU lockup fix — do in order)
#      1. GPU hardware fixes (PSR, Wayland, runtime PM, backlight perms)
#      2. Smart blank script (requires #1: backlight perms, video group)
#      3. GDM startup fix
#      4. GNOME settings (requires #2: idle-delay=0 because smart-blank handles it)
#
#   B. HIBERNATE (do in order)
#      5. Swap resize to 64GB
#      6. GRUB resume parameters (requires #5: swap UUID and offset)
#      7. Systemd hibernate config (requires #5: swap exists)
#      8. ACPI wakeup devices (requires hibernate functional)
#      9. Lid close action (requires #6-#8: hibernate fully working)
#
#-------------------------------------------------------------------------------

SECTION_COUNT=9

declare -A STATUS
declare -A DETAIL
NEEDS_REBOOT=false
NEEDS_INITRAMFS=false

#-------------------------------------------------------------------------------
# Labels and group headers
#-------------------------------------------------------------------------------
declare -A LABELS
LABELS[1]="GPU hardware fixes (PSR, Wayland, runtime PM, backlight)"
LABELS[2]="Smart blank script (backlight control without DPMS)"
LABELS[3]="GDM startup fix (race condition workaround)"
LABELS[4]="GNOME power & desktop settings"
LABELS[5]="Swap resize (${SWAP_SIZE} for hibernate)"
LABELS[6]="GRUB hibernate resume parameters"
LABELS[7]="Systemd hibernate configuration"
LABELS[8]="ACPI wakeup device management"
LABELS[9]="Lid close → hibernate"

# Which sections each depends on (empty = no dependency)
declare -A DEPENDS
DEPENDS[1]=""
DEPENDS[2]="1"
DEPENDS[3]=""
DEPENDS[4]="2"
DEPENDS[5]=""
DEPENDS[6]="5"
DEPENDS[7]="5"
DEPENDS[8]="6 7"
DEPENDS[9]="6 7 8"

#-------------------------------------------------------------------------------
# Preflight
#-------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: Run as root (sudo bash $0)${NC}"
    exit 1
fi

if ! id "$USERNAME" &>/dev/null; then
    echo -e "${RED}ERROR: User $USERNAME does not exist${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
# Check functions
#-------------------------------------------------------------------------------

check_1() {  # GPU fixes
    local done=true
    local details=""

    if [ -f /etc/modprobe.d/i915.conf ] && grep -q "enable_psr=0" /etc/modprobe.d/i915.conf 2>/dev/null; then
        details+="  PSR disabled: YES\n"
    else
        details+="  PSR disabled: NO\n"
        done=false
    fi

    if grep -q "^WaylandEnable=false" /etc/gdm3/custom.conf 2>/dev/null; then
        details+="  Wayland disabled: YES\n"
    else
        details+="  Wayland disabled: NO\n"
        done=false
    fi

    if [ -f /etc/udev/rules.d/80-gpu-no-runtime-pm.rules ]; then
        details+="  GPU runtime PM udev rule: YES\n"
    else
        details+="  GPU runtime PM udev rule: NO\n"
        done=false
    fi

    if [ -f /etc/systemd/system/systemd-hibernate.service.d/gpu-fix.conf ]; then
        details+="  Hibernate GPU fix: YES\n"
    else
        details+="  Hibernate GPU fix: NO\n"
        done=false
    fi

    if [ -f /etc/udev/rules.d/90-backlight.rules ]; then
        details+="  Backlight udev rule: YES\n"
    else
        details+="  Backlight udev rule: NO\n"
        done=false
    fi

    if id -nG "$USERNAME" 2>/dev/null | grep -qw video; then
        details+="  $USERNAME in video group: YES\n"
    else
        details+="  $USERNAME in video group: NO\n"
        done=false
    fi

    DETAIL[1]="$details"
    $done && STATUS[1]="done" || STATUS[1]="not done"
}

check_2() {  # Smart blank
    local done=true
    local details=""

    if dpkg -l xprintidle 2>/dev/null | grep -q "^ii"; then
        details+="  xprintidle installed: YES\n"
    else
        details+="  xprintidle installed: NO\n"
        done=false
    fi

    if [ -f /usr/local/bin/smart-blank.sh ]; then
        details+="  smart-blank.sh script: YES\n"
    else
        details+="  smart-blank.sh script: NO\n"
        done=false
    fi

    if [ -f /etc/systemd/system/smart-blank.service ]; then
        if systemctl is-enabled smart-blank.service &>/dev/null; then
            details+="  smart-blank.service: ENABLED\n"
        else
            details+="  smart-blank.service: EXISTS but NOT ENABLED\n"
            done=false
        fi
    else
        details+="  smart-blank.service: NO\n"
        done=false
    fi

    DETAIL[2]="$details"
    $done && STATUS[2]="done" || STATUS[2]="not done"
}

check_3() {  # GDM fix
    local done=true
    local details=""

    if [ -f /etc/systemd/system/gdm-fix.service ]; then
        if systemctl is-enabled gdm-fix.service &>/dev/null; then
            details+="  gdm-fix.service: ENABLED\n"
        else
            details+="  gdm-fix.service: EXISTS but NOT ENABLED\n"
            done=false
        fi
    else
        details+="  gdm-fix.service: NO\n"
        done=false
    fi

    DETAIL[3]="$details"
    $done && STATUS[3]="done" || STATUS[3]="not done"
}

check_4() {  # GNOME settings
    local done=true
    local details=""

    local uid
    uid=$(id -u "$USERNAME")
    local gs_cmd="sudo -u $USERNAME env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus gsettings"

    local idle_delay
    idle_delay=$($gs_cmd get org.gnome.desktop.session idle-delay 2>/dev/null | awk '{print $NF}')
    if [ "$idle_delay" = "0" ]; then
        details+="  idle-delay: 0 (smart-blank handles blanking)\n"
    else
        details+="  idle-delay: ${idle_delay:-unknown} (should be 0)\n"
        done=false
    fi

    local bat_suspend
    bat_suspend=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 2>/dev/null)
    if [ "$bat_suspend" = "'hibernate'" ]; then
        details+="  Battery idle action: hibernate\n"
    else
        details+="  Battery idle action: ${bat_suspend:-unknown} (should be 'hibernate')\n"
        done=false
    fi

    local bat_timeout
    bat_timeout=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 2>/dev/null | awk '{print $NF}')
    if [ "$bat_timeout" = "1800" ]; then
        details+="  Battery idle timeout: 1800s (30 min)\n"
    else
        details+="  Battery idle timeout: ${bat_timeout:-unknown}s (should be 1800)\n"
        done=false
    fi

    # UPower critical battery settings
    local crit_action
    crit_action=$(grep "^CriticalPowerAction=" /etc/UPower/UPower.conf 2>/dev/null | cut -d= -f2)
    if [ "$crit_action" = "Hibernate" ]; then
        details+="  Critical battery action: Hibernate\n"
    else
        details+="  Critical battery action: ${crit_action:-unknown} (should be Hibernate)\n"
        done=false
    fi

    local pct_action
    pct_action=$(grep "^PercentageAction=" /etc/UPower/UPower.conf 2>/dev/null | cut -d= -f2)
    if [ "$pct_action" = "5" ]; then
        details+="  Action battery percentage: 5%\n"
    else
        details+="  Action battery percentage: ${pct_action:-unknown}% (should be 5)\n"
        done=false
    fi

    local ac_suspend
    ac_suspend=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 2>/dev/null)
    if [ "$ac_suspend" = "'nothing'" ]; then
        details+="  AC auto-suspend: disabled\n"
    else
        details+="  AC auto-suspend: ${ac_suspend:-unknown}\n"
        done=false
    fi

    local edge_tiling
    edge_tiling=$($gs_cmd get org.gnome.mutter edge-tiling 2>/dev/null)
    if [ "$edge_tiling" = "false" ]; then
        details+="  Edge tiling: disabled\n"
    else
        details+="  Edge tiling: ${edge_tiling:-unknown}\n"
        done=false
    fi

    DETAIL[4]="$details"
    $done && STATUS[4]="done" || STATUS[4]="not done"
}

check_5() {  # Swap
    local done=true
    local details=""

    local swap_gb_needed
    swap_gb_needed=$(echo "$SWAP_SIZE" | grep -o "[0-9]*")

    if swapon --show | grep -q "/swap.img"; then
        local file_bytes
        file_bytes=$(stat -c%s /swap.img 2>/dev/null || echo 0)
        local file_gb=$(( file_bytes / 1024 / 1024 / 1024 ))

        if [ "$file_gb" -ge "$swap_gb_needed" ]; then
            details+="  Swap file: ${file_gb}GB, active (OK)\n"
        else
            details+="  Swap file: ${file_gb}GB, active (need ${swap_gb_needed}GB)\n"
            done=false
        fi
    elif [ -f /swap.img ]; then
        local file_bytes
        file_bytes=$(stat -c%s /swap.img 2>/dev/null || echo 0)
        local file_gb=$(( file_bytes / 1024 / 1024 / 1024 ))
        details+="  Swap file: ${file_gb}GB, NOT ACTIVE\n"
        done=false
    else
        details+="  Swap file: DOES NOT EXIST\n"
        done=false
    fi

    DETAIL[5]="$details"
    $done && STATUS[5]="done" || STATUS[5]="not done"
}

check_6() {  # GRUB resume
    local done=true
    local details=""

    if grep -q "resume=UUID=" /etc/default/grub 2>/dev/null; then
        local params
        params=$(grep "GRUB_CMDLINE_LINUX_DEFAULT" /etc/default/grub | grep -o "resume[^ \"]*" | tr '\n' ' ')
        details+="  Resume params: $params\n"
    else
        details+="  Resume params: NOT SET\n"
        done=false
    fi

    DETAIL[6]="$details"
    $done && STATUS[6]="done" || STATUS[6]="not done"
}

check_7() {  # Hibernate config
    local done=true
    local details=""

    local conf="/etc/systemd/sleep.conf"
    for setting in AllowHibernation AllowSuspendThenHibernate; do
        if grep -q "^${setting}=yes" "$conf" 2>/dev/null; then
            details+="  $setting: YES\n"
        else
            details+="  $setting: NO\n"
            done=false
        fi
    done

    DETAIL[7]="$details"
    $done && STATUS[7]="done" || STATUS[7]="not done"
}

check_8() {  # ACPI wakeup
    local done=true
    local details=""

    if [ -f /etc/systemd/system/disable-wakeup.service ]; then
        if systemctl is-enabled disable-wakeup.service &>/dev/null; then
            details+="  disable-wakeup.service: ENABLED\n"
        else
            details+="  disable-wakeup.service: EXISTS but NOT ENABLED\n"
            done=false
        fi
    else
        details+="  disable-wakeup.service: NO\n"
        done=false
    fi

    for dev in LID0 GLAN XHC; do
        if grep -q "${dev}.*enabled" /proc/acpi/wakeup 2>/dev/null; then
            details+="  $dev: ENABLED (disabled on next boot)\n"
        elif grep -q "${dev}.*disabled" /proc/acpi/wakeup 2>/dev/null; then
            details+="  $dev: disabled\n"
        fi
    done

    DETAIL[8]="$details"
    $done && STATUS[8]="done" || STATUS[8]="not done"
}

check_9() {  # Lid close
    local done=true
    local details=""

    for s in HandleLidSwitch HandleLidSwitchExternalPower HandleLidSwitchDocked; do
        if grep -q "^${s}=hibernate" /etc/systemd/logind.conf 2>/dev/null; then
            details+="  $s: hibernate\n"
        else
            local current
            current=$(grep "^${s}=" /etc/systemd/logind.conf 2>/dev/null | cut -d= -f2)
            details+="  $s: ${current:-NOT SET}\n"
            done=false
        fi
    done

    DETAIL[9]="$details"
    $done && STATUS[9]="done" || STATUS[9]="not done"
}

run_all_checks() {
    for i in $(seq 1 $SECTION_COUNT); do
        check_$i
    done
}

#-------------------------------------------------------------------------------
# Apply functions
#-------------------------------------------------------------------------------

apply_1() {  # GPU fixes
    echo ""
    echo -e "${CYAN}Applying GPU / display fixes...${NC}"

    if [ -f /etc/modprobe.d/i915.conf ] && grep -q "enable_psr=0" /etc/modprobe.d/i915.conf; then
        echo "  /etc/modprobe.d/i915.conf already correct"
    else
        cat > /etc/modprobe.d/i915.conf << 'EOF'
options i915 enable_psr=0
EOF
        echo "  Created /etc/modprobe.d/i915.conf"
        NEEDS_INITRAMFS=true
    fi

    if [ -f /etc/gdm3/custom.conf ]; then
        sed -i 's/^#*WaylandEnable=.*/WaylandEnable=false/' /etc/gdm3/custom.conf
        echo "  Wayland disabled"
    fi

    cat > /etc/udev/rules.d/80-gpu-no-runtime-pm.rules << 'EOF'
ACTION=="add", SUBSYSTEM=="pci", ATTR{vendor}=="0x8086", ATTR{class}=="0x030000", ATTR{power/control}="on"
EOF
    echo "  GPU runtime PM udev rule created"

    # Force GPU out of runtime suspend before hibernate to prevent i915 crash
    mkdir -p /etc/systemd/system/systemd-hibernate.service.d
    cat > /etc/systemd/system/systemd-hibernate.service.d/gpu-fix.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c "echo on > /sys/bus/pci/devices/0000:00:02.0/power/control"
EOF
    echo "  Hibernate GPU fix created"

    cat > /etc/udev/rules.d/90-backlight.rules << 'EOF'
ACTION=="add", SUBSYSTEM=="backlight", RUN+="/bin/chgrp video /sys/class/backlight/%k/brightness"
ACTION=="add", SUBSYSTEM=="backlight", RUN+="/bin/chmod g+w /sys/class/backlight/%k/brightness"
EOF
    echo "  Backlight udev rule created"

    usermod -aG video "$USERNAME"
    echo "  Added $USERNAME to video group"

    # Clean up old GPU runtime PM overrides if present
    rm -f /usr/lib/systemd/system-sleep/gpu-power.sh
    rm -rf /etc/systemd/system/power-profiles-daemon.service.d
    if systemctl is-enabled gpu-no-runtime-pm.service &>/dev/null; then
        systemctl disable gpu-no-runtime-pm.service
        rm -f /etc/systemd/system/gpu-no-runtime-pm.service
    fi
    systemctl daemon-reload

    NEEDS_REBOOT=true
    echo -e "${GREEN}  Done${NC}"
}

apply_2() {  # Smart blank
    echo ""
    echo -e "${CYAN}Applying smart blank script...${NC}"

    apt install -y xprintidle > /dev/null 2>&1
    echo "  Installed xprintidle"

    cat > /usr/local/bin/smart-blank.sh << 'SCRIPT'
#!/bin/bash
BACKLIGHT=/sys/class/backlight/intel_backlight
IDLE_TIMEOUT=300
STATE_FILE=/tmp/.screen_blanked
BRIGHTNESS_FILE=/tmp/.saved_brightness

# Wait for X session to be ready
XAUTH=""
DISPLAY=""
for i in $(seq 1 60); do
    if [ -f "/run/user/$(id -u)/gdm/Xauthority" ]; then
        XAUTH="/run/user/$(id -u)/gdm/Xauthority"
    elif [ -f "$HOME/.Xauthority" ]; then
        XAUTH="$HOME/.Xauthority"
    fi

    # Detect display from gnome-shell process
    gnome_pid=$(pgrep -u $(id -u) gnome-shell 2>/dev/null | head -1)
    if [ -n "$gnome_pid" ]; then
        DISPLAY=$(cat /proc/$gnome_pid/environ 2>/dev/null | tr '\0' '\n' | grep ^DISPLAY= | cut -d= -f2)
    fi
    if [ -z "$DISPLAY" ]; then
        DISPLAY=":0"
    fi

    if [ -n "$XAUTH" ] && DISPLAY="$DISPLAY" XAUTHORITY="$XAUTH" xset q >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

export DISPLAY
export XAUTHORITY="$XAUTH"

# Verify X connection
if ! xset q >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to X display after 120s" >&2
    exit 1
fi

# Disable DPMS
xset -dpms
xset s off

while true; do
    IDLE_MS=$(xprintidle 2>/dev/null)
    if [ -z "$IDLE_MS" ]; then
        sleep 5
        continue
    fi
    IDLE=$(( IDLE_MS / 1000 ))

    if [ "$IDLE" -ge "$IDLE_TIMEOUT" ] && [ ! -f "$STATE_FILE" ]; then
        echo 0 > "$BACKLIGHT/brightness"
        touch "$STATE_FILE"
    elif [ "$IDLE" -lt 5 ] && [ -f "$STATE_FILE" ]; then
        cat "$BACKLIGHT/max_brightness" > "$BACKLIGHT/brightness"
        rm -f "$STATE_FILE"
    fi

    sleep 5
done
SCRIPT

    # Apply configured timeout
    sed -i "s/IDLE_TIMEOUT=300/IDLE_TIMEOUT=${SCREEN_IDLE_TIMEOUT}/" /usr/local/bin/smart-blank.sh

    chmod +x /usr/local/bin/smart-blank.sh
    echo "  Created smart-blank.sh"

    cat > /etc/systemd/system/smart-blank.service << EOF
[Unit]
Description=Smart screen blanking without DPMS
After=graphical.target

[Service]
Type=simple
User=${USERNAME}
ExecStart=/usr/local/bin/smart-blank.sh
Restart=always
RestartSec=10

[Install]
WantedBy=graphical.target
EOF

    systemctl daemon-reload
    systemctl enable smart-blank.service
    if systemctl is-active smart-blank.service &>/dev/null; then
        systemctl restart smart-blank.service
        echo "  Restarted smart-blank.service"
    else
        echo "  Enabled smart-blank.service (starts on next boot)"
        NEEDS_REBOOT=true
    fi
    echo -e "${GREEN}  Done${NC}"
}

apply_3() {  # GDM fix
    echo ""
    echo -e "${CYAN}Applying GDM startup fix...${NC}"

    cat > /etc/systemd/system/gdm-fix.service << 'EOF'
[Unit]
Description=Restart GDM if session fails
After=gdm.service
Wants=gdm.service

[Service]
Type=oneshot
ExecStartPre=/bin/sleep 20
ExecStart=/bin/bash -c "for i in 1 2 3; do pgrep -x gnome-shell > /dev/null && exit 0; systemctl restart gdm3; sleep 15; done"

[Install]
WantedBy=graphical.target
EOF

    systemctl daemon-reload
    systemctl enable gdm-fix.service
    echo "  Enabled gdm-fix.service"
    NEEDS_REBOOT=true
    echo -e "${GREEN}  Done${NC}"
}

apply_4() {  # GNOME settings
    echo ""
    echo -e "${CYAN}Applying GNOME settings...${NC}"

    local uid
    uid=$(id -u "$USERNAME")
    local gs_cmd="sudo -u $USERNAME env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus gsettings"

    $gs_cmd set org.gnome.desktop.session idle-delay 0
    $gs_cmd set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 'hibernate'
    $gs_cmd set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 1800
    $gs_cmd set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'
    $gs_cmd set org.gnome.mutter edge-tiling false

    # UPower critical battery settings
    sed -i 's/^CriticalPowerAction=.*/CriticalPowerAction=Hibernate/' /etc/UPower/UPower.conf
    sed -i 's/^PercentageAction=.*/PercentageAction=5/' /etc/UPower/UPower.conf
    systemctl restart upower

    echo "  idle-delay: 0"
    echo "  Battery idle: hibernate after 30 min"
    echo "  Critical battery: hibernate at 5% (UPower)"
    echo "  AC auto-suspend: disabled"
    echo "  Edge tiling: disabled"
    echo -e "${GREEN}  Done${NC}"
}

apply_5() {  # Swap
    echo ""
    echo -e "${CYAN}Resizing swap to ${SWAP_SIZE}...${NC}"

    # Skip if swap already exists at correct size
    local swap_gb_needed
    swap_gb_needed=$(echo "$SWAP_SIZE" | grep -o "[0-9]*")

    if [ -f /swap.img ]; then
        local file_gb=$(( $(stat -c%s /swap.img) / 1024 / 1024 / 1024 ))
        if [ "$file_gb" -ge "$swap_gb_needed" ] && swapon --show | grep -q "/swap.img"; then
            echo "  Swap already ${file_gb}GB and active — skipping"
            echo -e "${GREEN}  Done${NC}"
            return
        fi
    fi

    if swapon --show | grep -q "/swap.img"; then
        echo "  Disabling current swap..."
        swapoff /swap.img || { echo -e "${RED}  ERROR: swapoff failed${NC}"; return 1; }
    fi

    echo "  Allocating ${SWAP_SIZE} (this may take a moment)..."
    if ! fallocate -l "$SWAP_SIZE" /swap.img; then
        echo -e "${RED}  ERROR: fallocate failed. Trying dd instead...${NC}"
        dd if=/dev/zero of=/swap.img bs=1G count="$swap_gb_needed" status=progress || { echo -e "${RED}  ERROR: dd also failed${NC}"; return 1; }
    fi

    chmod 600 /swap.img
    echo "  Formatting swap..."
    mkswap /swap.img || { echo -e "${RED}  ERROR: mkswap failed${NC}"; return 1; }
    echo "  Enabling swap..."
    swapon /swap.img || { echo -e "${RED}  ERROR: swapon failed${NC}"; return 1; }

    if ! grep -q "/swap.img" /etc/fstab; then
        echo "/swap.img none swap sw 0 0" >> /etc/fstab
        echo "  Added swap to /etc/fstab"
    fi

    echo "  Verifying..."
    swapon --show
    echo -e "${GREEN}  Done${NC}"
}

apply_6() {  # GRUB resume
    echo ""
    echo -e "${CYAN}Configuring GRUB resume parameters...${NC}"

    local uuid offset
    uuid=$(findmnt -no UUID -T /swap.img)
    offset=$(filefrag -v /swap.img | awk '$1=="0:" {print substr($4, 1, length($4)-2)}')

    if [ -z "$uuid" ] || [ -z "$offset" ]; then
        echo -e "${RED}  ERROR: Could not determine swap UUID or offset${NC}"
        echo -e "${RED}  Is the swap file active? Run section 5 first.${NC}"
        return 1
    fi

    if grep -q "resume=UUID=${uuid}.*resume_offset=${offset}" /etc/default/grub; then
        echo "  Resume parameters already correct"
    elif grep -q "resume=UUID=" /etc/default/grub; then
        echo "  Updating stale resume parameters..."
        sed -i "s/resume=UUID=[^ \"]*/resume=UUID=$uuid/" /etc/default/grub
        sed -i "s/resume_offset=[^ \"]*/resume_offset=$offset/" /etc/default/grub
        echo "  Updated to resume=UUID=$uuid resume_offset=$offset"
    else
        sed -i "s/\(GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*\)/\1 resume=UUID=$uuid resume_offset=$offset/" /etc/default/grub
        echo "  Added resume=UUID=$uuid resume_offset=$offset"
    fi

    update-grub
    NEEDS_REBOOT=true
    NEEDS_INITRAMFS=true
    echo -e "${GREEN}  Done${NC}"
}

apply_7() {  # Hibernate config
    echo ""
    echo -e "${CYAN}Configuring systemd hibernate...${NC}"

    local conf="/etc/systemd/sleep.conf"

    if ! grep -q '^\[Sleep\]' "$conf" 2>/dev/null; then
        echo "[Sleep]" >> "$conf"
    fi

    for setting in AllowHibernation AllowSuspendThenHibernate; do
        if grep -q "^${setting}=yes" "$conf"; then
            echo "  $setting already set"
        else
            sed -i "/^#*${setting}=/d" "$conf"
            sed -i "/^\[Sleep\]/a ${setting}=yes" "$conf"
            echo "  $setting set to yes"
        fi
    done

    echo -e "${GREEN}  Done${NC}"
}

apply_8() {  # ACPI wakeup
    echo ""
    echo -e "${CYAN}Configuring ACPI wakeup devices...${NC}"

    cat > /etc/systemd/system/disable-wakeup.service << 'EOF'
[Unit]
Description=Disable ACPI wakeup devices
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "for dev in LID0 GLAN XHC; do grep -q \"$dev.*enabled\" /proc/acpi/wakeup && echo $dev > /proc/acpi/wakeup; done"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable disable-wakeup.service
    echo "  Enabled disable-wakeup.service"
    echo "  NOTE: Power button required to wake from hibernate"
    NEEDS_REBOOT=true
    echo -e "${GREEN}  Done${NC}"
}

apply_9() {  # Lid close
    echo ""
    echo -e "${CYAN}Setting lid close to hibernate...${NC}"

    for s in HandleLidSwitch HandleLidSwitchExternalPower HandleLidSwitchDocked; do
        if grep -q "^${s}=hibernate" /etc/systemd/logind.conf; then
            echo "  $s already set"
        else
            sed -i "s/^#*${s}=.*/${s}=hibernate/" /etc/systemd/logind.conf
            echo "  $s set to hibernate"
        fi
    done

    NEEDS_REBOOT=true
    echo -e "${GREEN}  Done${NC}"
}

#-------------------------------------------------------------------------------
# Dependency check
#-------------------------------------------------------------------------------
check_deps() {
    local section=$1
    local deps="${DEPENDS[$section]}"
    local missing=""

    if [ -z "$deps" ]; then
        return 0
    fi

    for dep in $deps; do
        if [ "${STATUS[$dep]}" != "done" ]; then
            missing+="    ${dep}. ${LABELS[$dep]}\n"
        fi
    done

    if [ -n "$missing" ]; then
        echo ""
        echo -e "${YELLOW}  Section $section requires these to be completed first:${NC}"
        echo -e "$missing"
        read -rp "  Continue anyway? [y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            return 1
        fi
    fi

    return 0
}

#-------------------------------------------------------------------------------
# Apply a single section with dependency and confirmation check
#-------------------------------------------------------------------------------
apply_section() {
    local n=$1

    if [ "${STATUS[$n]}" = "done" ]; then
        echo ""
        echo -e "${YELLOW}  Section $n is already complete. Re-apply anyway? [y/n]: ${NC}"
        read -rp "  " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            return
        fi
    fi

    check_deps "$n" || return

    apply_$n
}

#-------------------------------------------------------------------------------
# Display menu
#-------------------------------------------------------------------------------
show_menu() {
    echo ""
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}  Dell Latitude 5490 Ubuntu 24.04 Setup  v${VERSION}${NC}"
    echo -e "${BOLD}============================================================${NC}"

    # Group A: Display
    echo ""
    echo -e "${BOLD}  A. DISPLAY (GPU lockup fix)${NC}"
    print_menu_line 1
    print_menu_line 2
    print_menu_line 3
    print_menu_line 4

    # Group B: Hibernate
    echo ""
    echo -e "${BOLD}  B. HIBERNATE${NC}"
    print_menu_line 5
    print_menu_line 6
    print_menu_line 7
    print_menu_line 8
    print_menu_line 9

    echo ""
    echo -e "  ${BOLD} A${NC}  Apply ALL incomplete sections (in order)"
    echo -e "  ${BOLD} D${NC}  Show details for all sections"
    echo -e "  ${BOLD} R${NC}  Refresh status"
    echo -e "  ${BOLD} F${NC}  Finalize (rebuild initramfs + reboot prompt)"
    echo -e "  ${BOLD} Q${NC}  Quit"

    if $NEEDS_INITRAMFS || $NEEDS_REBOOT; then
        echo ""
        $NEEDS_INITRAMFS && echo -e "  ${RED}▸ initramfs rebuild pending${NC}"
        $NEEDS_REBOOT && echo -e "  ${RED}▸ Reboot required for changes to take effect${NC}"
    fi

    echo ""
}

print_menu_line() {
    local i=$1

    if [ "${STATUS[$i]}" = "done" ]; then
        local mark="${GREEN}✓${NC}"
    else
        local mark="${RED}✗${NC}"
    fi

    # Show dependency hint for incomplete items
    local dep_hint=""
    if [ "${STATUS[$i]}" != "done" ] && [ -n "${DEPENDS[$i]}" ]; then
        local unmet=false
        for dep in ${DEPENDS[$i]}; do
            if [ "${STATUS[$dep]}" != "done" ]; then
                unmet=true
                break
            fi
        done
        if $unmet; then
            dep_hint="${DIM} (needs ${DEPENDS[$i]})${NC}"
        fi
    fi

    printf "  %b  ${BOLD}%2d${NC}. %s%b\n" "$mark" "$i" "${LABELS[$i]}" "$dep_hint"
}

#-------------------------------------------------------------------------------
# Show details
#-------------------------------------------------------------------------------
show_details() {
    echo ""

    echo -e "${BOLD}  A. DISPLAY${NC}"
    for i in 1 2 3 4; do
        print_detail $i
    done

    echo -e "${BOLD}  B. HIBERNATE${NC}"
    for i in 5 6 7 8 9; do
        print_detail $i
    done

    read -rp "Press Enter to continue..."
}

print_detail() {
    local i=$1
    if [ "${STATUS[$i]}" = "done" ]; then
        echo -e "${GREEN}  [✓] ${i}. ${LABELS[$i]}${NC}"
    else
        echo -e "${RED}  [✗] ${i}. ${LABELS[$i]}${NC}"
    fi
    echo -e "${DETAIL[$i]}"
}

#-------------------------------------------------------------------------------
# Apply all incomplete in dependency order
#-------------------------------------------------------------------------------
apply_all_incomplete() {
    local count=0
    for i in $(seq 1 $SECTION_COUNT); do
        [ "${STATUS[$i]}" != "done" ] && ((count++)) || true
    done

    if [ "$count" -eq 0 ]; then
        echo ""
        echo -e "${GREEN}  All sections already complete.${NC}"
        read -rp "  Press Enter to continue..."
        return
    fi

    echo ""
    echo -e "${YELLOW}  Will apply $count incomplete section(s) in order:${NC}"
    for i in $(seq 1 $SECTION_COUNT); do
        if [ "${STATUS[$i]}" != "done" ]; then
            echo "    ${i}. ${LABELS[$i]}"
        fi
    done
    echo ""
    read -rp "  Proceed? [y/n]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        return
    fi

    for i in $(seq 1 $SECTION_COUNT); do
        if [ "${STATUS[$i]}" != "done" ]; then
            apply_$i
            check_$i
        fi
    done

    echo ""
    echo -e "${CYAN}  Rebuilding initramfs...${NC}"
    update-initramfs -u
    echo -e "${GREEN}  initramfs rebuilt${NC}"

    run_all_checks
    echo ""
    read -rp "  Press Enter to continue..."
}

#-------------------------------------------------------------------------------
# Finalize
#-------------------------------------------------------------------------------
finalize() {
    echo ""
    echo -e "${CYAN}Rebuilding initramfs...${NC}"
    update-initramfs -u
    NEEDS_INITRAMFS=false
    echo -e "${GREEN}  Done${NC}"

    echo ""
    echo -e "${BOLD}  Post-reboot verification:${NC}"
    echo "    1. cat /sys/module/i915/parameters/enable_psr            (should be 0)"
    echo "    2. cat /sys/bus/pci/devices/0000:00:02.0/power/control   (should be on)"
    echo "    3. systemctl status smart-blank                          (should be active)"
    echo "    4. sudo systemctl hibernate                              (test hibernate)"
    echo "    5. Close lid, wait 2 min, open lid, press power          (test lid close)"
    echo ""

    read -rp "  Create post-reboot verification script? [y/n]: " create_verify
    if [[ "$create_verify" =~ ^[Yy] ]]; then
        create_verify_script
    fi

    echo ""
    read -rp "  Reboot now? [y/n]: " confirm
    if [[ "$confirm" =~ ^[Yy] ]]; then
        reboot
    fi
}

create_verify_script() {
    local script_dir
    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    local verify_path="${script_dir}/verify-dell-5490.sh"

    cat > "$verify_path" << 'VERIFY'
#!/bin/bash
#===============================================================================
# Dell Latitude 5490 Post-Reboot Verification
# Run after reboot to confirm all setup changes took effect.
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$(whoami)" = "root" ]; then
    echo -e "${RED}ERROR: Do not run as root${NC}"
    echo "  This script must run as the logged-in desktop user."
    echo "  Usage: ./verify-dell-5490.sh"
    echo "  Do NOT use sudo."
    exit 1
fi

PASS=0
FAIL=0

check() {
    local desc="$1"
    local result="$2"
    local expected="$3"

    if [ "$result" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $desc: $result"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} $desc: $result (expected: $expected)"
        ((FAIL++))
    fi
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Dell Latitude 5490 Post-Reboot Verification${NC}"
echo -e "${BOLD}============================================================${NC}"

echo ""
echo -e "${BOLD}  DISPLAY${NC}"

# PSR disabled
psr=$(sudo cat /sys/module/i915/parameters/enable_psr 2>/dev/null)
check "PSR disabled" "$psr" "0"

# GPU runtime PM udev rule
if [ -f /etc/udev/rules.d/80-gpu-no-runtime-pm.rules ]; then
    echo -e "  ${GREEN}✓${NC} GPU runtime PM udev rule: present"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} GPU runtime PM udev rule: missing"
    ((FAIL++))
fi

# Hibernate GPU fix
if [ -f /etc/systemd/system/systemd-hibernate.service.d/gpu-fix.conf ]; then
    echo -e "  ${GREEN}✓${NC} Hibernate GPU fix: present"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} Hibernate GPU fix: missing"
    ((FAIL++))
fi

# Wayland disabled
wayland=$(grep "^WaylandEnable=" /etc/gdm3/custom.conf 2>/dev/null | cut -d= -f2)
check "Wayland disabled" "$wayland" "false"

# Display server
session_type=$(echo $XDG_SESSION_TYPE)
check "Session type" "$session_type" "x11"

# Smart-blank service
sb_active=$(systemctl is-active smart-blank.service 2>/dev/null)
check "smart-blank.service" "$sb_active" "active"

# Smart-blank connected to X
sb_tasks=$(systemctl show smart-blank.service -p TasksCurrent --value 2>/dev/null)
if [ "$sb_tasks" -ge 2 ] 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} smart-blank tasks: $sb_tasks (running)"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} smart-blank tasks: ${sb_tasks:-0} (may not be connected to X)"
    ((FAIL++))
fi

# DPMS disabled
dpms=$(DISPLAY=${DISPLAY:-:1} xset q 2>/dev/null | grep "DPMS is" | awk '{print $NF}')
check "DPMS" "$dpms" "Disabled"

# GDM fix service
gdm_enabled=$(systemctl is-enabled gdm-fix.service 2>/dev/null)
check "gdm-fix.service" "$gdm_enabled" "enabled"

# Backlight writable
if [ -w /sys/class/backlight/intel_backlight/brightness ]; then
    echo -e "  ${GREEN}✓${NC} Backlight writable: yes"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} Backlight writable: no (check video group / udev rule)"
    ((FAIL++))
fi

echo ""
echo -e "${BOLD}  HIBERNATE${NC}"

# Swap
swap_needed=$(( $(awk '/MemTotal/ {print int($2 / 1024 / 1024) + 1}' /proc/meminfo) ))
swap_active=$(swapon --show --noheadings 2>/dev/null | grep -c swap)
if [ "$swap_active" -ge 1 ]; then
    swap_gb=$(( $(stat -c%s /swap.img 2>/dev/null || echo 0) / 1024 / 1024 / 1024 ))
    if [ "$swap_gb" -ge "$swap_needed" ]; then
        echo -e "  ${GREEN}✓${NC} Swap file: ${swap_gb}GB active (need ${swap_needed}GB+)"
        ((PASS++))
    else
        echo -e "  ${RED}✗${NC} Swap file: ${swap_gb}GB active (need ${swap_needed}GB+)"
        ((FAIL++))
    fi
else
    echo -e "  ${RED}✗${NC} Swap: not active"
    ((FAIL++))
fi

# GRUB resume
if grep -q "resume=UUID=" /etc/default/grub 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} GRUB resume parameters: set"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} GRUB resume parameters: not set"
    ((FAIL++))
fi

# Hibernate allowed
hib_allow=$(grep "^AllowHibernation=yes" /etc/systemd/sleep.conf 2>/dev/null)
if [ -n "$hib_allow" ]; then
    echo -e "  ${GREEN}✓${NC} AllowHibernation: yes"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} AllowHibernation: not set"
    ((FAIL++))
fi

# ACPI wakeup service
wakeup_enabled=$(systemctl is-enabled disable-wakeup.service 2>/dev/null)
check "disable-wakeup.service" "$wakeup_enabled" "enabled"

# LID0 disabled
lid_state=$(grep "LID0" /proc/acpi/wakeup 2>/dev/null | awk '{print $3}')
if [ "$lid_state" = "*disabled" ] || [ "$lid_state" = "disabled" ]; then
    echo -e "  ${GREEN}✓${NC} LID0 wakeup: disabled"
    ((PASS++))
else
    echo -e "  ${RED}✗${NC} LID0 wakeup: ${lid_state:-unknown} (should be disabled)"
    ((FAIL++))
fi

# Lid close action
lid_switch=$(grep "^HandleLidSwitch=" /etc/systemd/logind.conf 2>/dev/null | cut -d= -f2)
check "HandleLidSwitch" "$lid_switch" "hibernate"

echo ""
echo -e "${BOLD}  GNOME SETTINGS${NC}"

gs_cmd="gsettings"
idle_delay=$($gs_cmd get org.gnome.desktop.session idle-delay 2>/dev/null | awk '{print $NF}')
check "idle-delay" "$idle_delay" "0"

bat_type=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 2>/dev/null)
check "Battery idle action" "$bat_type" "'hibernate'"

bat_timeout=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 2>/dev/null | awk '{print $NF}')
check "Battery idle timeout" "${bat_timeout}s" "1800s"

crit_action=$(grep "^CriticalPowerAction=" /etc/UPower/UPower.conf 2>/dev/null | cut -d= -f2)
check "Critical battery action" "$crit_action" "Hibernate"

pct_action=$(grep "^PercentageAction=" /etc/UPower/UPower.conf 2>/dev/null | cut -d= -f2)
check "Action battery percentage" "${pct_action}%" "5%"

ac_type=$($gs_cmd get org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 2>/dev/null)
check "AC idle action" "$ac_type" "'nothing'"

edge=$($gs_cmd get org.gnome.mutter edge-tiling 2>/dev/null)
check "Edge tiling" "$edge" "false"

# Summary
echo ""
echo -e "${BOLD}============================================================${NC}"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}All $TOTAL checks passed.${NC}"
else
    echo -e "  ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC} out of $TOTAL checks."
fi
echo -e "${BOLD}============================================================${NC}"

echo ""
echo -e "${BOLD}  Manual tests (cannot be automated):${NC}"
echo "    1. sudo systemctl hibernate        (test hibernate)"
echo "    2. Close lid, wait 2 min, press power button (test lid close)"
echo "    3. Wait 5 min idle on AC           (backlight should turn off)"
echo "    4. Wait 30 min idle on battery    (should hibernate)"
echo ""

exit $FAIL
VERIFY

    chmod +x "$verify_path"
    echo ""
    echo -e "${GREEN}  Created: ${verify_path}${NC}"
    echo "  Run after reboot:  ${verify_path}"
}

#-------------------------------------------------------------------------------
# Main loop
#-------------------------------------------------------------------------------
run_all_checks

while true; do
    show_menu
    read -rp "  Select [1-9, A, D, R, F, Q]: " choice

    case "$choice" in
        [1-9])
            apply_section "$choice"
            run_all_checks
            echo ""
            read -rp "  Press Enter to continue..."
            ;;
        [Aa])
            apply_all_incomplete
            ;;
        [Dd])
            show_details
            ;;
        [Rr])
            run_all_checks
            ;;
        [Ff])
            finalize
            ;;
        [Qq])
            echo ""
            incomplete=0
            for i in $(seq 1 $SECTION_COUNT); do
                [ "${STATUS[$i]}" != "done" ] && ((incomplete++)) || true
            done
            if [ "$incomplete" -gt 0 ]; then
                echo -e "${YELLOW}  Warning: $incomplete section(s) incomplete${NC}"
            fi
            if $NEEDS_INITRAMFS; then
                echo -e "${RED}  WARNING: initramfs rebuild required but not done.${NC}"
                echo -e "${RED}           Changes to GRUB/i915 will NOT take effect until you run:${NC}"
                echo -e "${RED}           sudo update-initramfs -u${NC}"
            fi
            if $NEEDS_REBOOT; then
                echo -e "${RED}  WARNING: Reboot required for changes to take effect.${NC}"
                echo -e "${RED}           Services, udev rules, GRUB, and logind changes${NC}"
                echo -e "${RED}           are not active until after reboot.${NC}"
                echo ""
                read -rp "  Reboot now? [y/n]: " confirm
                if [[ "$confirm" =~ ^[Yy] ]]; then
                    if $NEEDS_INITRAMFS; then
                        echo "  Rebuilding initramfs first..."
                        update-initramfs -u
                    fi
                    reboot
                fi
            fi
            echo "  Goodbye."
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}  Invalid selection${NC}"
            sleep 1
            ;;
    esac
done
