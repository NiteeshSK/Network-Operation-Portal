"""
arp_parser.py — Parsers for switch ARP tables.

Returns a list of dicts:
  {
    "ip_address":  str,
    "mac_address": str (lowercased, normalized to xx:xx:xx:xx:xx:xx),
    "interface":   str,
    "vlan":        str,
    "arp_type":    str,  # 'Dynamic' / 'Static' / ''
    "age_seconds": int,
  }
"""
import re


_MAC_NORM_RE = re.compile(r"[^0-9a-fA-F]")


def _normalize_mac(mac: str) -> str:
    """Convert any common MAC format to xx:xx:xx:xx:xx:xx."""
    if not mac:
        return ""
    hex_chars = _MAC_NORM_RE.sub("", mac)
    if len(hex_chars) != 12:
        return mac.lower()
    return ":".join(hex_chars[i:i+2] for i in range(0, 12, 2)).lower()


# ─────────────────────────────────────────────────────────────────────
# Comware — `display arp`
# ─────────────────────────────────────────────────────────────────────
# Sample:
#   Type: S-Static  D-Dynamic  O-Openflow  R-Rule   M-Multiport  I-Invalid
#   IP address       MAC address    VLAN/VSI name  Interface             Aging Type
#   10.25.51.231     aabb-ccdd-eeff 100            Ten-GigabitEthernet1/0/1 20    D
#
def parse_comware_arp(raw: str) -> list[dict]:
    rows = []
    if not raw:
        return rows
    in_table = False
    type_map = {"D": "Dynamic", "S": "Static", "O": "Openflow",
                "R": "Rule", "M": "Multiport", "I": "Invalid"}
    for line in raw.splitlines():
        if "IP address" in line and "MAC address" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip() or line.startswith("Type:"):
            continue

        tokens = line.split()
        if len(tokens) < 5:
            continue
        # Heuristic: tokens[0] looks like an IP
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]):
            continue

        ip   = tokens[0]
        mac  = tokens[1]

        # Aging + Type are the last two tokens. Type is a letter code; aging int.
        ttype_code = tokens[-1]
        ttype = type_map.get(ttype_code, ttype_code)
        try:
            aging = int(tokens[-2])
        except ValueError:
            aging = 0

        # The middle tokens (between MAC and aging) hold the VLAN/VSI column
        # and the Interface column. On L2 access ports the VLAN is a number;
        # on routed (L3) interfaces like FGE/Route-Aggregation the VLAN column
        # is blank, so only the interface is present. Decide column-by-column:
        #   - a purely-numeric token  -> VLAN
        #   - a token with letters '/' -> interface name
        middle = tokens[2:-2]
        vlan = ""
        iface = ""
        for tok in middle:
            if tok in ("--", "N/A"):
                continue
            if re.match(r"^\d+$", tok):
                # pure number = VLAN id (only take the first one seen)
                if not vlan:
                    vlan = tok
                else:
                    iface = (iface + " " + tok).strip()
            else:
                # interface name (FGE1/0/52, Ten-GigabitEthernet1/0/1, Vlan-interface100, ...)
                iface = (iface + " " + tok).strip()

        # Some Comware builds print the VLAN embedded as "Vlan-interfaceNNN" or
        # "Vlanif100" in the interface column with no separate VLAN number.
        if not vlan:
            m = re.search(r"[Vv]lan(?:-interface|if)?(\d+)", iface)
            if m:
                vlan = m.group(1)

        rows.append({
            "ip_address":  ip,
            "mac_address": _normalize_mac(mac),
            "interface":   iface,
            "vlan":        vlan,
            "arp_type":    ttype,
            "age_seconds": aging,
        })
    return rows


# ─────────────────────────────────────────────────────────────────────
# Aruba (AOS-CX, AOS-S, ProVision) — `show arp`
# ─────────────────────────────────────────────────────────────────────
# AOS-CX sample (varies a bit by version):
#
#   IPv4 Address     MAC                 Port           Physical Port    State
#   ----------------------------------------------------------------------------
#   10.25.51.2       aa:bb:cc:dd:ee:ff   vlan10         1/1/49           reachable
#   10.25.51.3       11:22:33:44:55:66   vlan10         1/1/50           reachable
#
def parse_aruba_arp(raw: str) -> list[dict]:
    rows = []
    if not raw:
        return rows
    in_table = False
    for line in raw.splitlines():
        s = line.strip()
        if "IPv4 Address" in line and "MAC" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if not s or s.startswith("---") or s.startswith("==="):
            continue

        tokens = line.split()
        if len(tokens) < 3:
            continue
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]):
            continue

        ip = tokens[0]
        mac = tokens[1]
        # AOS-CX 'Port' is often a vlan or interface label.
        port_label = tokens[2] if len(tokens) >= 3 else ""
        phys = tokens[3] if len(tokens) >= 4 else ""
        # State is usually the last token ('reachable', 'stale', 'failed')
        # If present, assume it's the last one when len >= 5
        vlan = ""
        if port_label.lower().startswith("vlan"):
            vlan = port_label.replace("vlan", "").replace("Vlan", "").strip() or port_label

        rows.append({
            "ip_address":  ip,
            "mac_address": _normalize_mac(mac),
            "interface":   phys or port_label,
            "vlan":        vlan,
            "arp_type":    "Dynamic",
            "age_seconds": 0,
        })
    return rows


# ─────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────
ARP_PARSERS = {
    "hp_comware":     ("display arp", parse_comware_arp),
    "huawei":         ("display arp", parse_comware_arp),
    "huawei_vrp":     ("display arp", parse_comware_arp),
    "aruba_aoscx":    ("show arp",    parse_aruba_arp),
    "aruba_os":       ("show arp",    parse_aruba_arp),
    "aruba_osswitch": ("show arp",    parse_aruba_arp),
    "aruba_procurve": ("show arp",    parse_aruba_arp),
}


def get_arp_command_and_parser(device_type: str):
    return ARP_PARSERS.get(device_type, ("display arp", parse_comware_arp))