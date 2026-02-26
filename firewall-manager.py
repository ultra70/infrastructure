#!/usr/bin/python3
"""
Firewall Manager — GTK4/Adwaita GUI for nftables firewall management

OVERVIEW
    A single self-contained Python script that provides a graphical interface
    for managing nftables firewall rules on Linux desktops. Designed as a
    replacement for UFW, which silently whitelists mDNS (UDP 5353) and SSDP
    (UDP 1900) traffic via hidden ACCEPT rules in /etc/ufw/before.rules that
    execute before user-defined rules and cannot be overridden through normal
    UFW commands.

ARCHITECTURE
    The GUI runs as a normal user. A persistent privileged helper process is
    launched once at startup via pkexec (polkit), which handles all root
    operations over a JSON-over-stdin/stdout protocol. This avoids running
    GTK as root (which breaks Wayland) and eliminates repeated password
    prompts. The helper is terminated when the GUI window is closed.

    No temporary files are created. The script calls itself via pkexec with
    an internal --privileged-daemon flag. The helper validates all input
    before executing any privileged operation.

WHAT THIS SCRIPT DOES
    - Generates and applies nftables rulesets to /etc/nftables.conf
    - Enables and starts nftables.service for persistence across reboots
    - Stops, disables, and masks ufw.service to prevent conflicts
    - Stops, disables, and masks firewalld.service if present
    - Masks or unmasks avahi-daemon.service and avahi-daemon.socket based
      on user configuration
    - These changes persist across reboots

WHAT THIS SCRIPT DOES NOT DO
    - Filter outbound traffic (OUTPUT chain policy is always accept)
    - Manage IPv6-specific rules beyond the inet family table
    - Replace iptables rules injected by Docker, libvirt, or fail2ban
    - Provide rate limiting, connection tracking tuning, or logging

FIREWALL MODES
    Accept All  — policy accept on all chains, no filtering
    Selective   — policy drop with explicit accept rules for toggled services
    Lockdown    — policy drop, no inbound exceptions (loopback and
                  established/related connections are always permitted)

HOW TO REVERT
    Use the Reset option in the hamburger menu, or manually:
        sudo nft flush ruleset
        sudo systemctl stop nftables && sudo systemctl disable nftables
        sudo systemctl unmask ufw.service avahi-daemon.service avahi-daemon.socket
        sudo systemctl start avahi-daemon.socket

DEPENDENCIES
    All are included by default on Ubuntu 24.04 GNOME Desktop:
        python3-gi      — GObject introspection bindings
        gir1.2-gtk-4.0  — GTK 4 typelib
        gir1.2-adw-1    — libadwaita typelib
        nftables        — nft command-line tool (/usr/sbin/nft)
        polkit          — pkexec for privilege escalation

PLATFORM
    Developed and tested on Ubuntu 24.04.4 LTS with GNOME desktop.
    Requires systemd, polkit (pkexec), and nftables. Command paths are
    hardcoded to /usr/sbin/ which is standard on Debian/Ubuntu. Other
    distributions may require path adjustments.

USAGE
    ./firewall-manager.py              Launch GUI
    ./firewall-manager.py -h --help    Show help
    ./firewall-manager.py -v --version Show version

LICENSE
    See LICENSE file in the repository.

SOURCE
    https://github.com/...  (update with actual repo URL)
"""

import sys
import os
import json
import re
import subprocess
import threading

VERSION = "1.0.0"

# =============================================================================
# Absolute paths — required because pkexec uses a minimal PATH
# =============================================================================

NFT = "/usr/sbin/nft"
IPTABLES_SAVE = "/usr/sbin/iptables-save"
IP6TABLES_SAVE = "/usr/sbin/ip6tables-save"
ARPTABLES_SAVE = "/usr/sbin/arptables-save"
EBTABLES_SAVE = "/usr/sbin/ebtables-save"
UFW = "/usr/sbin/ufw"
FIREWALL_CMD = "/usr/bin/firewall-cmd"
SYSTEMCTL = "/usr/bin/systemctl"

# =============================================================================
# Service definitions
# =============================================================================

SERVICES = [
    {
        "id": "ssh",
        "label": "SSH / SFTP",
        "description": "Remote shell and file transfer (TCP 22)",
        "ports": [["tcp", "22"]],
        "needs_avahi": False,
    },
    {
        "id": "samba",
        "label": "Samba",
        "description": "Windows file sharing (TCP 139,445 / UDP 137,138)",
        "ports": [["tcp", "139"], ["tcp", "445"], ["udp", "137"], ["udp", "138"]],
        "needs_avahi": False,
    },
    {
        "id": "nfs",
        "label": "NFS",
        "description": "Network File System (TCP/UDP 2049)",
        "ports": [["tcp", "2049"], ["udp", "2049"]],
        "needs_avahi": False,
    },
    {
        "id": "ftp",
        "label": "FTP",
        "description": "File transfer (TCP 21)",
        "ports": [["tcp", "21"]],
        "needs_avahi": False,
    },
    {
        "id": "vnc",
        "label": "VNC",
        "description": "Remote desktop (TCP 5900-5910)",
        "ports": [["tcp", "5900-5910"]],
        "needs_avahi": False,
    },
    {
        "id": "rdp",
        "label": "RDP",
        "description": "Remote desktop (TCP/UDP 3389)",
        "ports": [["tcp", "3389"], ["udp", "3389"]],
        "needs_avahi": False,
    },
    {
        "id": "kde-connect",
        "label": "KDE Connect / GSConnect",
        "description": "Phone integration (TCP/UDP 1714-1764)",
        "ports": [["tcp", "1714-1764"], ["udp", "1714-1764"]],
        "needs_avahi": False,
    },
    {
        "id": "syncthing",
        "label": "Syncthing",
        "description": "File sync (TCP 22000 / UDP 21027)",
        "ports": [["tcp", "22000"], ["udp", "22000"], ["udp", "21027"]],
        "needs_avahi": False,
    },
    {
        "id": "chromecast",
        "label": "Chromecast / Casting",
        "description": "Cast discovery and control (mDNS + TCP 8008-8009)",
        "ports": [["udp", "5353"], ["tcp", "8008-8009"], ["tcp", "8443"]],
        "needs_avahi": True,
    },
    {
        "id": "printer-discovery",
        "label": "Printer Discovery",
        "description": "Network printer auto-discovery (mDNS + CUPS 631)",
        "ports": [["udp", "5353"], ["udp", "631"], ["tcp", "631"]],
        "needs_avahi": True,
    },
]

AVAHI_UNITS = ["avahi-daemon.socket", "avahi-daemon.service"]
NFTABLES_CONF = "/etc/nftables.conf"

FIREWALL_SUBSYSTEMS = [
    {
        "id": "nftables",
        "label": "nftables",
        "description": "Native netfilter rule engine (kernel 3.13+)",
        "cmd": [NFT, "list", "ruleset"],
        "managed": True,
    },
    {
        "id": "iptables",
        "label": "iptables (IPv4)",
        "description": "Legacy IPv4 packet filter (nft backend on 24.04)",
        "cmd": [IPTABLES_SAVE],
        "managed": False,
    },
    {
        "id": "ip6tables",
        "label": "ip6tables (IPv6)",
        "description": "Legacy IPv6 packet filter (nft backend on 24.04)",
        "cmd": [IP6TABLES_SAVE],
        "managed": False,
    },
    {
        "id": "arptables",
        "label": "arptables",
        "description": "ARP packet filter",
        "cmd": [ARPTABLES_SAVE],
        "managed": False,
    },
    {
        "id": "ebtables",
        "label": "ebtables",
        "description": "Ethernet bridge frame filter",
        "cmd": [EBTABLES_SAVE],
        "managed": False,
    },
    {
        "id": "ufw",
        "label": "UFW",
        "description": "Uncomplicated Firewall frontend",
        "cmd": [UFW, "status", "verbose"],
        "managed": False,
    },
    {
        "id": "firewalld",
        "label": "firewalld",
        "description": "Dynamic firewall manager (zone-based)",
        "cmd": [FIREWALL_CMD, "--list-all"],
        "managed": False,
    },
]


# =============================================================================
# Shared utilities
# =============================================================================


def run_cmd(cmd):
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", "not found"


def needs_avahi(service_ids):
    """Check if any selected service requires avahi."""
    return any(
        svc["needs_avahi"] for svc in SERVICES if svc["id"] in service_ids
    )


def generate_nftables_config(mode, enabled_service_ids=None, custom_rules=None):
    """Generate nftables.conf content based on mode.

    Modes:
        accept    — policy accept, no filtering
        selective — policy drop, allow specified services
        lockdown  — policy drop, no inbound exceptions
    """
    if enabled_service_ids is None:
        enabled_service_ids = set()
    if custom_rules is None:
        custom_rules = []

    if mode == "accept":
        return "\n".join([
            "#!/usr/sbin/nft -f",
            f"# Generated by Firewall Manager [mode: accept]",
            f"# [services: *]",
            "",
            "flush ruleset",
            "",
            "table inet firewall {",
            "",
            "    chain input {",
            "        type filter hook input priority filter; policy accept;",
            "    }",
            "",
            "    chain forward {",
            "        type filter hook forward priority filter; policy accept;",
            "    }",
            "",
            "    chain output {",
            "        type filter hook output priority filter; policy accept;",
            "    }",
            "}",
            "",
        ])

    if mode == "lockdown":
        return "\n".join([
            "#!/usr/sbin/nft -f",
            f"# Generated by Firewall Manager [mode: lockdown]",
            f"# [services: none]",
            "",
            "flush ruleset",
            "",
            "table inet firewall {",
            "",
            "    chain input {",
            "        type filter hook input priority filter; policy drop;",
            "",
            "        # Loopback",
            '        iif "lo" accept',
            "",
            "        # Established/related return traffic",
            "        ct state established,related accept",
            "",
            "        # Drop invalid",
            "        ct state invalid drop",
            "    }",
            "",
            "    chain forward {",
            "        type filter hook forward priority filter; policy drop;",
            "    }",
            "",
            "    chain output {",
            "        type filter hook output priority filter; policy accept;",
            "    }",
            "}",
            "",
        ])

    # mode == "selective"
    port_rules = set()
    for svc in SERVICES:
        if svc["id"] in enabled_service_ids:
            for p in svc["ports"]:
                port_rules.add((p[0], p[1]))
    for proto, port in custom_rules:
        port_rules.add((proto, port))

    want_avahi = needs_avahi(enabled_service_ids)

    svc_list = ",".join(sorted(enabled_service_ids)) if enabled_service_ids else "none"
    custom_list = ",".join(f"{p}:{pt}" for p, pt in custom_rules) if custom_rules else ""

    lines = [
        "#!/usr/sbin/nft -f",
        f"# Generated by Firewall Manager [mode: selective]",
        f"# [services: {svc_list}]",
    ]
    if custom_list:
        lines.append(f"# [custom: {custom_list}]")
    lines += [
        "",
        "flush ruleset",
        "",
        "table inet firewall {",
        "",
        "    chain input {",
        "        type filter hook input priority filter; policy drop;",
        "",
        "        # Loopback",
        '        iif "lo" accept',
        "",
        "        # Established/related return traffic",
        "        ct state established,related accept",
        "",
        "        # Drop invalid",
        "        ct state invalid drop",
    ]

    if port_rules:
        lines.append("")
        lines.append("        # Allowed inbound services")
        for proto, port in sorted(port_rules, key=lambda x: (x[0], x[1])):
            lines.append(f"        {proto} dport {port} accept")

    if want_avahi:
        lines.append("")
        lines.append("        # mDNS multicast (avahi-dependent services)")
        lines.append("        udp dport 5353 ip daddr 224.0.0.251 accept")
        lines.append("        udp dport 5353 ip6 daddr ff02::fb accept")

    lines += [
        "    }",
        "",
        "    chain forward {",
        "        type filter hook forward priority filter; policy drop;",
        "    }",
        "",
        "    chain output {",
        "        type filter hook output priority filter; policy accept;",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


# =============================================================================
# Privileged daemon — persistent root helper process (one pkexec prompt)
# =============================================================================


def privileged_daemon():
    """Run as root, read JSON commands from stdin, write responses to stdout.

    Protocol: one JSON object per line in, one JSON object per line out.
    Commands: {"cmd": "audit"}, {"cmd": "apply", "config": {...}}, {"cmd": "reset"}, {"cmd": "quit"}
    """
    # Signal ready — the GUI waits for this before sending commands
    _daemon_respond({"ready": True})

    while True:
        try:
            line = sys.stdin.readline()
        except Exception:
            break
        if not line:
            break  # EOF / pipe closed
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            _daemon_respond({"success": False, "message": f"Invalid JSON: {e}"})
            continue

        cmd = request.get("cmd", "")

        if cmd == "audit":
            _daemon_audit()
        elif cmd == "apply":
            _daemon_apply(request.get("config", {}))
        elif cmd == "reset":
            _daemon_reset()
        elif cmd == "set_avahi_unit":
            _daemon_set_avahi_unit(request.get("unit", ""), request.get("enable", False))
        elif cmd == "quit":
            break
        else:
            _daemon_respond({"success": False, "message": f"Unknown command: {cmd}"})


def _daemon_respond(obj):
    """Write a JSON response line to stdout."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _daemon_audit():
    """Collect all firewall subsystem data."""
    results = {}
    for sub in FIREWALL_SUBSYSTEMS:
        cmd_path = sub["cmd"][0]
        if not os.path.isfile(cmd_path):
            results[sub["id"]] = "__NOT_INSTALLED__"
            continue

        rc, stdout, stderr = run_cmd(sub["cmd"])
        if rc == 0:
            results[sub["id"]] = stdout
        elif "not found" in stderr:
            results[sub["id"]] = "__NOT_INSTALLED__"
        else:
            results[sub["id"]] = f"__ERROR__: {stderr}"

    _daemon_respond({"success": True, "data": results})


def _daemon_apply(config):
    """Apply firewall configuration."""
    service_ids = set(config.get("services", []))
    custom_rules = [tuple(r) for r in config.get("custom", [])]
    mode = config.get("mode", "selective")

    if mode not in ("accept", "selective", "lockdown"):
        _daemon_respond({"success": False, "message": f"Invalid mode: {mode}"})
        return

    valid_ids = {s["id"] for s in SERVICES}
    invalid = service_ids - valid_ids
    if invalid:
        _daemon_respond({"success": False, "message": f"Unknown services: {invalid}"})
        return

    for proto, port in custom_rules:
        if proto not in ("tcp", "udp"):
            _daemon_respond({"success": False, "message": f"Invalid protocol: {proto}"})
            return
        if not re.match(r"^\d+(-\d+)?$", port):
            _daemon_respond({"success": False, "message": f"Invalid port: {port}"})
            return

    errors = []

    # Disable UFW
    if os.path.isfile(UFW):
        rc, out, _ = run_cmd([UFW, "status"])
        if rc == 0 and "Status: active" in out:
            rc2, _, err = run_cmd([UFW, "disable"])
            if rc2 != 0:
                errors.append(f"ufw disable failed: {err}")
        run_cmd([SYSTEMCTL, "stop", "ufw.service"])
        run_cmd([SYSTEMCTL, "disable", "ufw.service"])
        run_cmd([SYSTEMCTL, "mask", "ufw.service"])

    # Disable firewalld
    rc, active, _ = run_cmd([SYSTEMCTL, "is-active", "firewalld.service"])
    if active.strip() == "active":
        run_cmd([SYSTEMCTL, "stop", "firewalld.service"])
        run_cmd([SYSTEMCTL, "mask", "firewalld.service"])

    # Handle avahi based on mode
    if mode == "accept":
        for unit in AVAHI_UNITS:
            run_cmd([SYSTEMCTL, "unmask", unit])
        run_cmd([SYSTEMCTL, "start", "avahi-daemon.socket"])
    elif mode == "lockdown":
        for unit in AVAHI_UNITS:
            run_cmd([SYSTEMCTL, "stop", unit])
            run_cmd([SYSTEMCTL, "mask", unit])
    else:
        want_avahi = needs_avahi(service_ids)
        if want_avahi:
            for unit in AVAHI_UNITS:
                run_cmd([SYSTEMCTL, "unmask", unit])
            run_cmd([SYSTEMCTL, "start", "avahi-daemon.socket"])
        else:
            for unit in AVAHI_UNITS:
                run_cmd([SYSTEMCTL, "stop", unit])
                run_cmd([SYSTEMCTL, "mask", unit])

    # Generate and write nftables config
    nft_content = generate_nftables_config(mode, service_ids, custom_rules)
    try:
        with open(NFTABLES_CONF, "w") as f:
            f.write(nft_content)
        os.chmod(NFTABLES_CONF, 0o644)
    except Exception as e:
        _daemon_respond({"success": False, "message": f"Write failed: {e}"})
        return

    # Apply
    rc, _, err = run_cmd([NFT, "-f", NFTABLES_CONF])
    if rc != 0:
        _daemon_respond({"success": False, "message": f"nft apply failed: {err}"})
        return

    run_cmd([SYSTEMCTL, "enable", "nftables.service"])
    run_cmd([SYSTEMCTL, "start", "nftables.service"])

    msg = "Configuration applied."
    if errors:
        msg += " Warnings: " + "; ".join(errors)
    _daemon_respond({"success": True, "message": msg})


def _daemon_reset():
    """Reset to defaults."""
    if os.path.isfile(NFT):
        run_cmd([NFT, "flush", "ruleset"])

    run_cmd([SYSTEMCTL, "disable", "nftables.service"])
    run_cmd([SYSTEMCTL, "stop", "nftables.service"])

    for unit in AVAHI_UNITS:
        run_cmd([SYSTEMCTL, "unmask", unit])
    run_cmd([SYSTEMCTL, "start", "avahi-daemon.socket"])

    run_cmd([SYSTEMCTL, "unmask", "ufw.service"])
    run_cmd([SYSTEMCTL, "unmask", "firewalld.service"])

    try:
        with open(NFTABLES_CONF, "w") as f:
            f.write("#!/usr/sbin/nft -f\nflush ruleset\n")
    except Exception as e:
        _daemon_respond({"success": False, "message": f"Write failed: {e}"})
        return

    _daemon_respond({"success": True, "message": "Reset to defaults. No firewall active."})


def _daemon_set_avahi_unit(unit, enable):
    """Enable or disable a specific avahi unit."""
    valid_units = {"avahi-daemon.service", "avahi-daemon.socket"}
    if unit not in valid_units:
        _daemon_respond({"success": False, "message": f"Invalid unit: {unit}"})
        return

    if enable:
        run_cmd([SYSTEMCTL, "unmask", unit])
        run_cmd([SYSTEMCTL, "enable", unit])
        run_cmd([SYSTEMCTL, "start", unit])
        _daemon_respond({"success": True, "message": f"{unit} enabled."})
    else:
        run_cmd([SYSTEMCTL, "stop", unit])
        run_cmd([SYSTEMCTL, "disable", unit])
        run_cmd([SYSTEMCTL, "mask", unit])
        _daemon_respond({"success": True, "message": f"{unit} disabled."})


# =============================================================================
# Privileged helper class — manages persistent root subprocess
# =============================================================================


def get_script_path():
    """Return absolute path to this script."""
    return os.path.abspath(__file__)


class PrivilegedHelper:
    """Manages a persistent privileged subprocess for root operations."""

    def __init__(self):
        self._proc = None
        self._lock = threading.Lock()

    def start(self):
        """Launch the privileged daemon via pkexec. Returns (True, "") or (False, error)."""
        try:
            self._proc = subprocess.Popen(
                ["pkexec", get_script_path(), "--privileged-daemon"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except Exception as e:
            return False, f"Failed to launch: {e}"

        # Wait for ready signal — blocks until user authenticates
        import select
        deadline = 60  # seconds
        try:
            while deadline > 0:
                # Check if process died (auth cancelled)
                if self._proc.poll() is not None:
                    stderr = self._proc.stderr.read()
                    return False, f"Process exited (code {self._proc.returncode}): {stderr[:200]}"

                ready_fds, _, _ = select.select([self._proc.stdout], [], [], 1.0)
                deadline -= 1
                if not ready_fds:
                    continue

                line = self._proc.stdout.readline()
                if not line:
                    return False, "Daemon closed stdout unexpectedly"

                line = line.strip()
                if not line:
                    continue

                # Skip non-JSON output (pkexec warnings etc)
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if resp.get("ready"):
                    return True, ""

            return False, "Timeout waiting for daemon"
        except Exception as e:
            if self._proc:
                self._proc.kill()
                self._proc = None
            return False, f"Startup error: {e}"

    def send(self, request):
        """Send a command dict, return response dict. Thread-safe."""
        with self._lock:
            if not self._proc or self._proc.poll() is not None:
                return {"success": False, "message": "Privileged helper not running"}

            try:
                self._proc.stdin.write(json.dumps(request) + "\n")
                self._proc.stdin.flush()
                line = self._proc.stdout.readline()
                if not line:
                    return {"success": False, "message": "Helper process closed"}
                return json.loads(line.strip())
            except Exception as e:
                return {"success": False, "message": str(e)}

    def audit(self):
        """Run audit, return dict of subsystem_id -> output or None."""
        resp = self.send({"cmd": "audit"})
        if resp.get("success") and "data" in resp:
            return resp["data"]
        return None

    def apply(self, mode, service_ids, custom_rules):
        """Apply config. Returns (success, message)."""
        config = {
            "mode": mode,
            "services": list(service_ids),
            "custom": [list(r) for r in custom_rules],
        }
        resp = self.send({"cmd": "apply", "config": config})
        return resp.get("success", False), resp.get("message", "")

    def reset(self):
        """Reset to defaults. Returns (success, message)."""
        resp = self.send({"cmd": "reset"})
        return resp.get("success", False), resp.get("message", "")

    def set_avahi_unit(self, unit, enable):
        """Enable or disable a specific avahi unit. Returns (success, message)."""
        resp = self.send({"cmd": "set_avahi_unit", "unit": unit, "enable": enable})
        return resp.get("success", False), resp.get("message", "")

    def stop(self):
        """Shut down the helper."""
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.stdin.write('{"cmd":"quit"}\n')
                self._proc.stdin.flush()
                self._proc.wait(timeout=5)
            except Exception:
                self._proc.kill()


# =============================================================================
# Unprivileged state readers
# =============================================================================


def get_unit_status(unit):
    _, enabled, _ = run_cmd([SYSTEMCTL, "is-enabled", unit])
    _, active, _ = run_cmd([SYSTEMCTL, "is-active", unit])
    return enabled.strip(), active.strip()


def get_daemon_statuses():
    daemons = {}
    for unit in AVAHI_UNITS + ["nftables.service", "ufw.service", "firewalld.service"]:
        e, a = get_unit_status(unit)
        daemons[unit] = {"enabled": e, "active": a}
    return daemons


def read_nftables_conf():
    try:
        with open(NFTABLES_CONF, "r") as f:
            return f.read()
    except (PermissionError, FileNotFoundError):
        return ""


def parse_allowed_ports(conf_text):
    allowed = set()
    for match in re.finditer(
        r"(tcp|udp)\s+dport\s+(\d+(?:-\d+)?)\s+accept", conf_text, re.IGNORECASE
    ):
        allowed.add((match.group(1).lower(), match.group(2)))
    return allowed


def detect_enabled_services(allowed_ports):
    enabled = set()
    for svc in SERVICES:
        svc_ports = {(p[0], p[1]) for p in svc["ports"]}
        if svc_ports.issubset(allowed_ports):
            enabled.add(svc["id"])
    return enabled


def detect_services_from_comment(conf_text):
    """Parse service IDs from the [services: ...] comment in config."""
    match = re.search(r"\[services:\s*([^\]]+)\]", conf_text)
    if not match:
        return None  # No comment found, fall back to port detection
    value = match.group(1).strip()
    if value == "*":
        return {s["id"] for s in SERVICES}
    if value == "none":
        return set()
    return set(value.split(","))


def detect_custom_from_comment(conf_text):
    """Parse custom rules from the [custom: ...] comment in config."""
    match = re.search(r"\[custom:\s*([^\]]+)\]", conf_text)
    if not match:
        return []
    pairs = match.group(1).strip().split(",")
    result = []
    for pair in pairs:
        parts = pair.strip().split(":", 1)
        if len(parts) == 2:
            result.append((parts[0], parts[1]))
    return sorted(result, key=lambda x: (x[0], x[1]))


def detect_custom_rules(allowed_ports, enabled_services):
    service_ports = set()
    for svc in SERVICES:
        if svc["id"] in enabled_services:
            for p in svc["ports"]:
                service_ports.add((p[0], p[1]))
    service_ports.add(("udp", "5353"))
    custom = [pp for pp in allowed_ports if pp not in service_ports]
    return sorted(custom, key=lambda x: (x[0], x[1]))


def detect_mode(conf_text):
    """Detect firewall mode from nftables.conf content."""
    if not conf_text:
        return None  # No config — no firewall active
    mode_match = re.search(r"\[mode:\s*(\w+)\]", conf_text)
    if mode_match:
        m = mode_match.group(1)
        if m in ("accept", "selective", "lockdown"):
            return m
    # Fallback: infer from policy
    if "policy accept" in conf_text and "policy drop" not in conf_text:
        return "accept"
    if "policy drop" in conf_text:
        if re.search(r"dport\s+\d", conf_text):
            return "selective"
        return "lockdown"
    return None


def analyze_subsystem(subsystem, raw_output):
    result = {
        "id": subsystem["id"],
        "label": subsystem["label"],
        "description": subsystem["description"],
        "available": True,
        "active": False,
        "managed": subsystem["managed"],
        "output": raw_output,
        "rule_count": 0,
        "warnings": [],
    }

    if raw_output is not None and raw_output.startswith("__NOT_INSTALLED__"):
        result["available"] = False
        result["output"] = "Not installed"
        return result

    if raw_output.startswith("__ERROR__"):
        result["output"] = raw_output.replace("__ERROR__: ", "")
        result["warnings"].append("Error reading rules")
        return result

    if subsystem["id"] == "nftables":
        result["active"] = bool(re.search(r"chain\s+\w+", raw_output))
        result["rule_count"] = len(
            re.findall(
                r"^\s+(tcp|udp|iif|ct state|type filter)", raw_output, re.MULTILINE
            )
        )
        # nft list ruleset strips comments — check config file on disk
        conf_on_disk = read_nftables_conf()
        if "Generated by Firewall Manager" in conf_on_disk or "Generated by harden-firewall" in conf_on_disk:
            result["managed"] = True
        else:
            result["managed"] = False
            if result["active"]:
                result["warnings"].append(
                    "nftables rules present but NOT generated by this tool"
                )

    elif subsystem["id"] in ("iptables", "ip6tables"):
        rules = [l.strip() for l in raw_output.splitlines() if l.strip().startswith("-A")]
        result["rule_count"] = len(rules)
        result["active"] = result["rule_count"] > 0

        docker_rules = [r for r in rules if "DOCKER" in r]
        ufw_rules = [r for r in rules if "ufw" in r.lower()]
        libvirt_rules = [r for r in rules if "LIBVIRT" in r or "virbr" in r]
        f2b_rules = [r for r in rules if "f2b" in r.lower() or "fail2ban" in r.lower()]

        if docker_rules:
            result["warnings"].append(
                f"Docker has injected {len(docker_rules)} iptables rules "
                f"(these bypass nftables and UFW)"
            )
        if ufw_rules:
            result["warnings"].append(f"UFW has {len(ufw_rules)} active iptables rules")
        if libvirt_rules:
            result["warnings"].append(
                f"libvirt has injected {len(libvirt_rules)} iptables rules"
            )
        if f2b_rules:
            result["warnings"].append(f"fail2ban has {len(f2b_rules)} active iptables rules")
        if result["active"] and not any([docker_rules, ufw_rules, libvirt_rules, f2b_rules]):
            result["warnings"].append("Unknown iptables rules detected — review manually")

    elif subsystem["id"] == "arptables":
        rules = [l for l in raw_output.splitlines() if l.strip().startswith("-")]
        result["rule_count"] = len(rules)
        result["active"] = result["rule_count"] > 0
        if result["active"]:
            result["warnings"].append("Active ARP filter rules — unusual on a desktop")

    elif subsystem["id"] == "ebtables":
        rules = [l for l in raw_output.splitlines() if l.strip().startswith("-")]
        result["rule_count"] = len(rules)
        result["active"] = result["rule_count"] > 0
        if result["active"]:
            result["warnings"].append("Active bridge filter rules detected")

    elif subsystem["id"] == "ufw":
        if "Status: active" in raw_output:
            result["active"] = True
            result["rule_count"] = raw_output.count("\n") - 4
            result["warnings"].append(
                "UFW is active — its hidden before.rules may conflict with nftables"
            )
        elif "Status: inactive" in raw_output:
            result["output"] = raw_output

    elif subsystem["id"] == "firewalld":
        if raw_output and not raw_output.startswith("__"):
            result["active"] = True
            result["warnings"].append(
                "firewalld is active — it will conflict with direct nftables management"
            )

    return result


# =============================================================================
# GUI
# =============================================================================


def run_gui():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")

    from gi.repository import Gtk, Adw, GLib, Gio

    CSS = """
    .status-active {
        color: @success_color;
        font-weight: bold;
    }
    .status-masked {
        color: @warning_color;
        font-weight: bold;
    }
    .status-inactive {
        color: @dim_label_color;
        font-weight: bold;
    }
    .status-unknown {
        color: @dim_label_color;
    }
    .warning-text {
        color: @error_color;
    }
    .audit-clean {
        color: @success_color;
        font-weight: bold;
    }
    .audit-warning {
        color: @warning_color;
        font-weight: bold;
    }
    .audit-alert {
        color: @error_color;
        font-weight: bold;
    }
    .audit-unavailable {
        color: @dim_label_color;
    }
    .monospace {
        font-family: monospace;
        font-size: 10pt;
    }
    .mode-btn {
        min-width: 120px;
        padding: 8px 16px;
        font-weight: bold;
        border-radius: 8px;
    }
    .mode-accept .mode-btn-accept,
    .mode-selective .mode-btn-selective,
    .mode-lockdown .mode-btn-lockdown {
        border: none;
    }
    .mode-btn-accept:checked {
        background: alpha(@success_color, 0.3);
        color: @success_color;
    }
    .mode-btn-selective:checked {
        background: alpha(@warning_color, 0.3);
        color: @warning_color;
    }
    .mode-btn-lockdown:checked {
        background: alpha(@error_color, 0.3);
        color: @error_color;
    }
    .mode-description {
        padding: 4px 0;
    }
    .switch-blocked switch {
        background: alpha(@error_color, 0.5);
    }
    .switch-blocked switch:checked {
        background: @error_color;
    }
    .switch-allowed switch {
        background: alpha(@success_color, 0.3);
    }
    .switch-allowed switch:checked {
        background: @success_color;
    }
    """

    class FirewallManagerWindow(Adw.ApplicationWindow):
        def __init__(self, **kwargs):
            super().__init__(
                title=f"Firewall Manager {VERSION}",
                default_width=750,
                default_height=950,
                **kwargs,
            )
            self.service_switches = {}
            self.custom_rules = []
            self._updating_switches = False
            self._updating_mode = False
            self._current_mode = None
            self._apply_timer_id = None
            self.audit_results = []
            self._cached_audit_data = None
            self.helper = PrivilegedHelper()

            self._build_ui()
            self._start_helper()

        def _start_helper(self):
            """Launch privileged daemon with single pkexec prompt."""
            self.loading_box.set_visible(True)
            self.content_box.set_visible(False)

            def worker():
                success, error = self.helper.start()
                if success:
                    data = self.helper.audit()
                    GLib.idle_add(self._audit_done, data, "")
                else:
                    GLib.idle_add(self._audit_done, None, error)

            threading.Thread(target=worker, daemon=True).start()

        def _build_ui(self):
            toolbar = Adw.ToolbarView()
            self.set_content(toolbar)

            header = Adw.HeaderBar()

            refresh_btn = Gtk.Button(icon_name="view-refresh-symbolic")
            refresh_btn.set_tooltip_text("Refresh")
            refresh_btn.connect("clicked", lambda _: self._refresh_state())
            header.pack_start(refresh_btn)

            menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic")
            menu = Gio.Menu()
            menu.append("Reset to Defaults", "win.reset")
            menu_btn.set_menu_model(menu)
            header.pack_end(menu_btn)

            reset_action = Gio.SimpleAction.new("reset", None)
            reset_action.connect("activate", self.on_reset)
            self.add_action(reset_action)

            toolbar.add_top_bar(header)

            scroll = Gtk.ScrolledWindow(vexpand=True)
            toolbar.set_content(scroll)

            main_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=24,
                margin_top=12,
                margin_bottom=24,
                margin_start=12,
                margin_end=12,
            )
            scroll.set_child(main_box)

            # Loading
            self.loading_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                halign=Gtk.Align.CENTER,
                valign=Gtk.Align.CENTER,
                spacing=12,
                margin_top=48,
                margin_bottom=48,
            )
            spinner = Gtk.Spinner(spinning=True)
            spinner.set_size_request(32, 32)
            self.loading_box.append(spinner)
            self.loading_box.append(
                Gtk.Label(label="Authenticating…")
            )
            main_box.append(self.loading_box)

            # Content
            self.content_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                spacing=24,
                visible=False,
            )
            main_box.append(self.content_box)

            # 1. Firewall mode selector
            mode_group = Adw.PreferencesGroup(
                title="Firewall Mode",
                description="Controls how inbound traffic is handled",
            )
            self.content_box.append(mode_group)

            self.mode_description = Gtk.Label(
                halign=Gtk.Align.START, wrap=True,
                margin_top=4, margin_bottom=8,
            )
            self.mode_description.add_css_class("mode-description")
            mode_group.add(self.mode_description)

            mode_btn_box = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL,
                spacing=0,
                halign=Gtk.Align.CENTER,
                margin_top=4,
                margin_bottom=4,
            )
            mode_btn_box.add_css_class("linked")
            mode_group.add(mode_btn_box)

            self.mode_btn_accept = Gtk.ToggleButton(label="Accept All")
            self.mode_btn_accept.add_css_class("mode-btn")
            self.mode_btn_accept.add_css_class("mode-btn-accept")
            mode_btn_box.append(self.mode_btn_accept)

            self.mode_btn_selective = Gtk.ToggleButton(
                label="Selective", group=self.mode_btn_accept,
            )
            self.mode_btn_selective.add_css_class("mode-btn")
            self.mode_btn_selective.add_css_class("mode-btn-selective")
            mode_btn_box.append(self.mode_btn_selective)

            self.mode_btn_lockdown = Gtk.ToggleButton(
                label="Lockdown", group=self.mode_btn_accept,
            )
            self.mode_btn_lockdown.add_css_class("mode-btn")
            self.mode_btn_lockdown.add_css_class("mode-btn-lockdown")
            mode_btn_box.append(self.mode_btn_lockdown)

            self.mode_btn_accept.connect("toggled", self._on_mode_toggled, "accept")
            self.mode_btn_selective.connect("toggled", self._on_mode_toggled, "selective")
            self.mode_btn_lockdown.connect("toggled", self._on_mode_toggled, "lockdown")

            # 2. Inbound services
            services_group = Adw.PreferencesGroup(
                title="Inbound Services",
                description="Toggle services to allow through the firewall (Selective mode only)",
            )
            self.content_box.append(services_group)

            for svc in SERVICES:
                row = Adw.SwitchRow(title=svc["label"], subtitle=svc["description"])
                row.add_css_class("switch-blocked")
                row.connect("notify::active", self._on_switch_toggled)
                services_group.add(row)
                self.service_switches[svc["id"]] = row

            # 3. Custom port rules
            custom_group = Adw.PreferencesGroup(
                title="Custom Port Rules",
                description="Allow arbitrary ports through the firewall",
            )
            self.content_box.append(custom_group)

            entry_row = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=4,
            )

            self.proto_dropdown = Gtk.DropDown.new_from_strings(["tcp", "udp"])
            self.proto_dropdown.set_selected(0)
            self.proto_dropdown.set_size_request(90, -1)
            entry_row.append(self.proto_dropdown)

            self.port_entry = Gtk.Entry(
                placeholder_text="Port or range (e.g., 8080 or 3000-3100)",
                hexpand=True,
            )
            self.port_entry.connect("activate", self.on_add_custom_rule)
            entry_row.append(self.port_entry)

            add_btn = Gtk.Button(icon_name="list-add-symbolic")
            add_btn.set_tooltip_text("Add custom rule")
            add_btn.connect("clicked", self.on_add_custom_rule)
            entry_row.append(add_btn)

            custom_group.add(entry_row)

            self.custom_list = Gtk.ListBox(
                selection_mode=Gtk.SelectionMode.NONE, margin_top=8,
            )
            self.custom_list.add_css_class("boxed-list")
            custom_group.add(self.custom_list)

            # 4. Application daemons
            app_daemon_group = Adw.PreferencesGroup(
                title="Application Daemons",
                description="Control background discovery services",
            )
            self.content_box.append(app_daemon_group)

            self.daemon_rows = {}
            self._updating_avahi = False

            self.avahi_service_switch = Adw.SwitchRow(
                title="Avahi Daemon",
                subtitle="mDNS/DNS-SD service — broadcasts hostname, discovers printers and cast devices",
            )
            self.avahi_service_switch.add_css_class("switch-blocked")
            self.avahi_service_switch.connect("notify::active", self._on_avahi_service_toggled)
            app_daemon_group.add(self.avahi_service_switch)

            self.avahi_socket_switch = Adw.SwitchRow(
                title="Avahi Socket",
                subtitle="Socket activation — auto-starts Avahi Daemon on demand",
            )
            self.avahi_socket_switch.add_css_class("switch-blocked")
            self.avahi_socket_switch.connect("notify::active", self._on_avahi_socket_toggled)
            app_daemon_group.add(self.avahi_socket_switch)

            # 5. Firewall daemons
            fw_daemon_group = Adw.PreferencesGroup(title="Firewall Daemons")
            self.content_box.append(fw_daemon_group)

            for unit, label in [
                ("nftables.service", "nftables"),
                ("ufw.service", "UFW"),
                ("firewalld.service", "firewalld"),
            ]:
                row = Adw.ActionRow(title=label, subtitle=unit)
                status_label = Gtk.Label(label="…", valign=Gtk.Align.CENTER)
                status_label.set_width_chars(14)
                row.add_suffix(status_label)
                fw_daemon_group.add(row)
                self.daemon_rows[unit] = status_label

            # 6. Firewall subsystem audit
            self.audit_group = Adw.PreferencesGroup(
                title="Firewall Subsystem Audit",
                description="Rules detected across all firewall subsystems",
            )
            self.content_box.append(self.audit_group)

            self.audit_summary_label = Gtk.Label(
                label="", halign=Gtk.Align.START, wrap=True,
                margin_top=4, margin_bottom=4,
            )
            self.audit_group.add(self.audit_summary_label)

            self.audit_list = Gtk.ListBox(
                selection_mode=Gtk.SelectionMode.NONE, margin_top=4,
            )
            self.audit_list.add_css_class("boxed-list")
            self.audit_group.add(self.audit_list)

            # 7. Managed nftables configuration
            rules_group = Adw.PreferencesGroup(title="Managed nftables Configuration")
            self.content_box.append(rules_group)

            rules_frame = Gtk.Frame(margin_top=4)
            self.rules_text = Gtk.TextView(
                editable=False, cursor_visible=False,
                wrap_mode=Gtk.WrapMode.NONE, monospace=True,
                top_margin=8, bottom_margin=8, left_margin=8, right_margin=8,
            )
            self.rules_text.add_css_class("monospace")
            rules_scroll = Gtk.ScrolledWindow(
                hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                vscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
            )
            rules_scroll.set_size_request(-1, 180)
            rules_scroll.set_child(self.rules_text)
            rules_frame.set_child(rules_scroll)
            rules_group.add(rules_frame)

            # Status bar
            status_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL,
                halign=Gtk.Align.CENTER, spacing=8, margin_top=12,
            )
            self.content_box.append(status_box)

            self.status_bar = Gtk.Label(
                label="", halign=Gtk.Align.CENTER, wrap=True,
            )
            status_box.append(self.status_bar)

        def _audit_done(self, audit_data, error=""):
            self._cached_audit_data = audit_data
            self.loading_box.set_visible(False)
            self.content_box.set_visible(True)
            if audit_data is None:
                self.status_bar.set_label(error or "Authentication failed or cancelled")
            self._refresh_ui()

        def _refresh_ui(self):
            daemons = get_daemon_statuses()
            for unit, label_widget in self.daemon_rows.items():
                info = daemons.get(unit, {"enabled": "unknown", "active": "unknown"})
                label_widget.set_label(f"{info['active']} / {info['enabled']}")

                for cls in ["status-active", "status-masked", "status-inactive", "status-unknown"]:
                    label_widget.remove_css_class(cls)

                if info["active"] == "active":
                    label_widget.add_css_class("status-active")
                elif info["enabled"] == "masked":
                    label_widget.add_css_class("status-masked")
                elif info["active"] == "inactive":
                    label_widget.add_css_class("status-inactive")
                else:
                    label_widget.add_css_class("status-unknown")

            # Update avahi toggles based on actual daemon state
            self._updating_avahi = True
            for unit, switch in [
                ("avahi-daemon.service", self.avahi_service_switch),
                ("avahi-daemon.socket", self.avahi_socket_switch),
            ]:
                info = daemons.get(unit, {})
                is_active = info.get("active") == "active" or info.get("enabled") not in ("masked", "disabled")
                switch.set_active(is_active)
                switch.remove_css_class("switch-blocked")
                switch.remove_css_class("switch-allowed")
                switch.add_css_class("switch-allowed" if is_active else "switch-blocked")
            self._updating_avahi = False

            self.audit_results = []
            if self._cached_audit_data:
                for sub in FIREWALL_SUBSYSTEMS:
                    raw = self._cached_audit_data.get(sub["id"], "")
                    self.audit_results.append(analyze_subsystem(sub, raw))
            else:
                for sub in FIREWALL_SUBSYSTEMS:
                    self.audit_results.append({
                        "id": sub["id"], "label": sub["label"],
                        "description": sub["description"],
                        "available": False, "active": False,
                        "managed": sub["managed"],
                        "output": "Authentication required",
                        "rule_count": 0,
                        "warnings": ["Could not read — authentication failed"],
                    })
            self._rebuild_audit_panel()

            conf = read_nftables_conf()
            self.rules_text.get_buffer().set_text(
                conf if conf else "(No nftables config found)"
            )

            # Prefer comment-based detection, fall back to port inference
            enabled = detect_services_from_comment(conf)
            if enabled is None:
                allowed = parse_allowed_ports(conf)
                enabled = detect_enabled_services(allowed)

            self._updating_switches = True
            for svc in SERVICES:
                self.service_switches[svc["id"]].set_active(svc["id"] in enabled)
            self._updating_switches = False

            custom_from_comment = detect_custom_from_comment(conf)
            if custom_from_comment is not None:
                self.custom_rules = custom_from_comment
            else:
                allowed = parse_allowed_ports(conf)
                self.custom_rules = detect_custom_rules(allowed, enabled)
            self._rebuild_custom_list()

            # Detect and set firewall mode
            detected_mode = detect_mode(conf)
            nft_active = any(
                r["id"] == "nftables" and r["active"] for r in self.audit_results
            )

            self._updating_mode = True
            if detected_mode == "accept":
                self.mode_btn_accept.set_active(True)
                self._current_mode = "accept"
            elif detected_mode == "lockdown":
                self.mode_btn_lockdown.set_active(True)
                self._current_mode = "lockdown"
            elif detected_mode == "selective":
                self.mode_btn_selective.set_active(True)
                self._current_mode = "selective"
            else:
                # No managed config — actual state is accept all
                self.mode_btn_accept.set_active(True)
                self._current_mode = "accept"
            self._updating_mode = False
            self._update_mode_ui()

        def _rebuild_audit_panel(self):
            while (child := self.audit_list.get_row_at_index(0)):
                self.audit_list.remove(child)

            total_warnings = 0
            unmanaged_active = 0

            for result in self.audit_results:
                row = Adw.ExpanderRow(
                    title=result["label"], subtitle=result["description"],
                )

                status_label = Gtk.Label(valign=Gtk.Align.CENTER)
                status_label.set_width_chars(16)

                if not result["available"]:
                    status_label.set_label("not installed")
                    status_label.add_css_class("audit-unavailable")
                elif not result["active"]:
                    status_label.set_label("no rules")
                    status_label.add_css_class("audit-clean")
                elif result["managed"]:
                    status_label.set_label(f"managed ({result['rule_count']} rules)")
                    status_label.add_css_class("audit-clean")
                elif result["warnings"]:
                    status_label.set_label(f"active ({result['rule_count']} rules)")
                    status_label.add_css_class("audit-alert")
                    unmanaged_active += 1
                    total_warnings += len(result["warnings"])
                else:
                    status_label.set_label(f"active ({result['rule_count']} rules)")
                    status_label.add_css_class("audit-warning")
                    unmanaged_active += 1

                row.add_suffix(status_label)

                for warning in result["warnings"]:
                    warn_row = Adw.ActionRow(title=warning)
                    warn_row.add_css_class("warning-text")
                    warn_row.add_prefix(
                        Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
                    )
                    row.add_row(warn_row)

                if result["output"] and result["available"]:
                    output_row = Adw.ActionRow()
                    output_label = Gtk.Label(
                        label=result["output"][:2000],
                        halign=Gtk.Align.START, valign=Gtk.Align.START,
                        wrap=True, selectable=True,
                        margin_top=4, margin_bottom=4,
                    )
                    output_label.add_css_class("monospace")
                    output_row.set_child(output_label)
                    row.add_row(output_row)

                self.audit_list.append(row)

            for cls in ["audit-clean", "audit-warning", "audit-alert"]:
                self.audit_summary_label.remove_css_class(cls)

            if total_warnings > 0:
                self.audit_summary_label.set_label(
                    f"⚠ {total_warnings} warning(s) across {unmanaged_active} "
                    f"unmanaged subsystem(s)"
                )
                self.audit_summary_label.add_css_class("audit-alert")
            elif unmanaged_active > 0:
                self.audit_summary_label.set_label(
                    f"⚠ {unmanaged_active} unmanaged subsystem(s) with active rules"
                )
                self.audit_summary_label.add_css_class("audit-warning")
            else:
                managed = sum(1 for r in self.audit_results if r["active"] and r["managed"])
                if managed > 0:
                    self.audit_summary_label.set_label(
                        "✓ All active rules are managed by this tool"
                    )
                    self.audit_summary_label.add_css_class("audit-clean")
                else:
                    self.audit_summary_label.set_label(
                        "No active firewall rules detected — all inbound traffic is accepted"
                    )
                    self.audit_summary_label.add_css_class("audit-alert")

        def _rebuild_custom_list(self):
            while (child := self.custom_list.get_row_at_index(0)):
                self.custom_list.remove(child)

            if not self.custom_rules:
                row = Adw.ActionRow(title="No custom rules")
                row.add_css_class("dim-label")
                self.custom_list.append(row)
                return

            for i, (proto, port) in enumerate(self.custom_rules):
                row = Adw.ActionRow(title=f"{proto.upper()} port {port}")
                btn = Gtk.Button(
                    icon_name="edit-delete-symbolic", valign=Gtk.Align.CENTER,
                )
                btn.add_css_class("flat")
                btn.connect("clicked", lambda _, j=i: self._remove_custom(j))
                row.add_suffix(btn)
                self.custom_list.append(row)

        def _schedule_apply(self):
            """Apply immediately in background thread."""
            # Cancel any pending apply
            if self._apply_timer_id is not None:
                GLib.source_remove(self._apply_timer_id)
                self._apply_timer_id = None
            self._flush_apply()

        def _flush_apply(self):
            """Apply current config immediately (synchronous)."""
            mode = self._current_mode
            if mode is None:
                return

            enabled_ids = set()
            if mode == "selective":
                for svc in SERVICES:
                    if self.service_switches[svc["id"]].get_active():
                        enabled_ids.add(svc["id"])

            custom = self.custom_rules if mode == "selective" else []

            self.status_bar.set_label("Applying…")

            def worker():
                success, message = self.helper.apply(mode, enabled_ids, custom)
                GLib.idle_add(self._apply_done, success, message)

            threading.Thread(target=worker, daemon=True).start()

        def _on_avahi_service_toggled(self, row, _pspec):
            if self._updating_avahi:
                return
            self._update_avahi_switch_color(row)
            enable = row.get_active()

            def worker():
                success, msg = self.helper.set_avahi_unit("avahi-daemon.service", enable)
                GLib.idle_add(self._avahi_done, success, msg)
            threading.Thread(target=worker, daemon=True).start()

        def _on_avahi_socket_toggled(self, row, _pspec):
            if self._updating_avahi:
                return
            self._update_avahi_switch_color(row)
            enable = row.get_active()

            def worker():
                success, msg = self.helper.set_avahi_unit("avahi-daemon.socket", enable)
                GLib.idle_add(self._avahi_done, success, msg)
            threading.Thread(target=worker, daemon=True).start()

        def _update_avahi_switch_color(self, row):
            row.remove_css_class("switch-blocked")
            row.remove_css_class("switch-allowed")
            row.add_css_class("switch-allowed" if row.get_active() else "switch-blocked")

        def _avahi_done(self, success, message):
            self.status_bar.set_label(message)
            self._refresh_state()

        def _on_switch_toggled(self, row, _pspec):
            row.remove_css_class("switch-blocked")
            row.remove_css_class("switch-allowed")
            if row.get_active():
                row.add_css_class("switch-allowed")
                # Auto-switch to selective if enabling a service in accept mode
                if not self._updating_switches and self._current_mode == "accept":
                    self._updating_mode = True
                    self.mode_btn_selective.set_active(True)
                    self._updating_mode = False
                    self._current_mode = "selective"
                    self._update_mode_ui()
                # Auto-switch to accept if all services now on in selective mode
                elif not self._updating_switches and self._current_mode == "selective":
                    all_on = all(
                        self.service_switches[s["id"]].get_active() for s in SERVICES
                    )
                    if all_on and not self.custom_rules:
                        self._updating_mode = True
                        self.mode_btn_accept.set_active(True)
                        self._updating_mode = False
                        self._current_mode = "accept"
                        self._update_mode_ui()
                if not self._updating_switches:
                    self._schedule_apply()
            else:
                row.add_css_class("switch-blocked")
                # Turning off a service in accept mode → switch to selective
                if not self._updating_switches and self._current_mode == "accept":
                    self._updating_mode = True
                    self.mode_btn_selective.set_active(True)
                    self._updating_mode = False
                    self._current_mode = "selective"
                    self._update_mode_ui()
                # Auto-switch back to accept if all services now off in selective
                elif not self._updating_switches and self._current_mode == "selective":
                    any_on = any(
                        self.service_switches[s["id"]].get_active() for s in SERVICES
                    )
                    if not any_on and not self.custom_rules:
                        self._updating_mode = True
                        self.mode_btn_accept.set_active(True)
                        self._updating_mode = False
                        self._current_mode = "accept"
                        self._update_mode_ui()
                if not self._updating_switches:
                    self._schedule_apply()

        def _on_mode_toggled(self, btn, mode):
            if not btn.get_active():
                return
            if self._updating_mode:
                return
            self._current_mode = mode
            self._update_mode_ui()
            self._schedule_apply()

        def _update_mode_ui(self):
            """Update UI elements based on current mode."""
            mode = self._current_mode

            # Update description
            for cls in ["audit-clean", "audit-alert", "warning-text", "audit-warning"]:
                self.mode_description.remove_css_class(cls)

            if mode == "accept":
                self.mode_description.set_label(
                    "All inbound traffic is accepted. No filtering is applied."
                )
                self.mode_description.add_css_class("audit-clean")
            elif mode == "selective":
                self.mode_description.set_label(
                    "All inbound traffic is blocked except for selected services below."
                )
                self.mode_description.add_css_class("audit-warning")
            elif mode == "lockdown":
                self.mode_description.set_label(
                    "All inbound traffic is blocked. No exceptions."
                )
                self.mode_description.add_css_class("audit-alert")
            else:
                self.mode_description.set_label(
                    "⚠ No firewall active — all ports are reachable. "
                    "Select a mode and apply."
                )
                self.mode_description.add_css_class("warning-text")

            # Update service switches
            if mode == "lockdown":
                self._updating_switches = True
                for svc in SERVICES:
                    sw = self.service_switches[svc["id"]]
                    sw.set_active(False)
                    sw.set_sensitive(False)
                    sw.remove_css_class("switch-allowed")
                    sw.remove_css_class("switch-blocked")
                    sw.add_css_class("switch-blocked")
                self._updating_switches = False
            elif mode == "accept":
                self._updating_switches = True
                for svc in SERVICES:
                    sw = self.service_switches[svc["id"]]
                    sw.set_active(True)
                    sw.set_sensitive(True)
                    sw.remove_css_class("switch-blocked")
                    sw.remove_css_class("switch-allowed")
                    sw.add_css_class("switch-allowed")
                self._updating_switches = False
            else:
                # Selective or None — keep switches interactive, colors reflect toggle state
                for svc in SERVICES:
                    sw = self.service_switches[svc["id"]]
                    sw.set_sensitive(True)
                    sw.remove_css_class("switch-blocked")
                    sw.remove_css_class("switch-allowed")
                    if sw.get_active():
                        sw.add_css_class("switch-allowed")
                    else:
                        sw.add_css_class("switch-blocked")

        def _remove_custom(self, index):
            if 0 <= index < len(self.custom_rules):
                self.custom_rules.pop(index)
                self._rebuild_custom_list()
                self._schedule_apply()

        def on_add_custom_rule(self, _widget):
            port_text = self.port_entry.get_text().strip()
            if not port_text:
                return

            if not re.match(r"^\d+(-\d+)?$", port_text):
                self.status_bar.set_label("Invalid format. Use port or range.")
                return

            parts = port_text.split("-")
            for p in parts:
                if not 1 <= int(p) <= 65535:
                    self.status_bar.set_label(f"Port {p} out of range (1-65535).")
                    return
            if len(parts) == 2 and int(parts[0]) >= int(parts[1]):
                self.status_bar.set_label("Invalid range.")
                return

            proto = "tcp" if self.proto_dropdown.get_selected() == 0 else "udp"
            rule = (proto, port_text)
            if rule not in self.custom_rules:
                self.custom_rules.append(rule)
                self.custom_rules.sort()
                self._rebuild_custom_list()
            self.port_entry.set_text("")
            self.status_bar.set_label("")
            self._schedule_apply()

        def _apply_done(self, success, message):
            self.status_bar.set_label(message)
            self._refresh_state()

        def _refresh_state(self):
            """Lightweight refresh — no loading spinner, updates in background."""
            def worker():
                data = self.helper.audit()
                GLib.idle_add(self._refresh_state_done, data)
            threading.Thread(target=worker, daemon=True).start()

        def _refresh_state_done(self, audit_data):
            self._cached_audit_data = audit_data
            self._refresh_ui()

        def on_reset(self, _action, _param):
            dialog = Adw.AlertDialog(
                heading="Reset Firewall?",
                body=(
                    "This removes all firewall rules, unmasks avahi-daemon, "
                    "UFW, and firewalld. No firewall will be active."
                ),
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("reset", "Reset")
            dialog.set_response_appearance("reset", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.connect("response", self._on_reset_response)
            dialog.present(self)

        def _on_reset_response(self, dialog, response):
            if response != "reset":
                return
            self.status_bar.set_label("Resetting…")

            def worker():
                success, message = self.helper.reset()
                GLib.idle_add(self._reset_done, success, message)

            threading.Thread(target=worker, daemon=True).start()

        def _reset_done(self, success, message):
            self.status_bar.set_label(message)
            self._refresh_state()

    class FirewallManagerApp(Adw.Application):
        def __init__(self):
            super().__init__(
                application_id="org.local.firewall-manager",
                flags=Gio.ApplicationFlags.FLAGS_NONE,
            )
            self.connect("activate", self.on_activate)

        def on_activate(self, app):
            css = Gtk.CssProvider()
            css.load_from_data(CSS.encode())
            win = self.get_active_window()
            if win:
                display = win.get_display()
            else:
                gi.require_version("Gdk", "4.0")
                from gi.repository import Gdk
                display = Gdk.Display.get_default()
            Gtk.StyleContext.add_provider_for_display(
                display, css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )
            win = FirewallManagerWindow(application=app)
            win.connect("close-request", self._on_close)
            win.present()

        def _on_close(self, win):
            win.helper.stop()
            return False

    app = FirewallManagerApp()
    app.run(None)


# =============================================================================
# Entry point
# =============================================================================

def main():
    if len(sys.argv) < 2:
        run_gui()
        return

    action = sys.argv[1]

    if action == "--privileged-daemon":
        if os.geteuid() != 0:
            print("Error: --privileged-daemon is an internal flag, not for direct use.", file=sys.stderr)
            print("Launch the GUI with no arguments instead.", file=sys.stderr)
            sys.exit(1)
        privileged_daemon()
    elif action in ("--version", "-v"):
        print(f"Firewall Manager {VERSION}")
    elif action in ("--help", "-h"):
        print(f"Firewall Manager {VERSION}")
        print(f"GTK4/Adwaita GUI for nftables firewall management")
        print()
        print(f"Usage: {sys.argv[0]} [OPTION]")
        print()
        print(f"Options:")
        print(f"  -h, --help       Show this help message")
        print(f"  -v, --version    Show version number")
        print()
        print(f"Running with no arguments launches the GUI.")
        print(f"Requires: python3-gi, gir1.2-gtk-4.0, gir1.2-adw-1, nftables")
        print(f"Tested on: Ubuntu 24.04 LTS")
    else:
        print(f"Unknown action: {action}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
