"""
port_stats_parser.py — Per-port input/output traffic counter parsers.

Supports:
  * HP Comware  : `display interface`           (verbose, per-interface block)
  * ArubaOS-CX  : `show interface statistics`   (tabular, one row per port)
  * Aruba PVOS  : `show interfaces <port>`      (per-port block)

All parsers return a list of dicts with the same shape:

  {
    "interface_name": str,
    "link_state":     str,   # may be "" for statistics-only outputs
    "in_packets":     int,
    "in_bytes":       int,
    "in_errors":      int,
    "in_broadcasts":  int,
    "out_packets":    int,
    "out_bytes":      int,
    "out_errors":     int,
    "out_broadcasts": int,
    "total_packets":  int,   # in_packets + out_packets, populated by every parser
  }
"""
import re


# ─────────────────────────────────────────────────────────────────────
# Comware — `display interface`
# ─────────────────────────────────────────────────────────────────────
def parse_comware_interface_detail(raw: str) -> list[dict]:
    """Parse Comware `display interface` (verbose) output.

    Splits the output into one block per interface by anchoring on lines
    that START WITH a known Comware interface name keyword
    (``FortyGigE1/0/52``, ``Ten-GigabitEthernet1/0/49:4`` etc.) at
    column 0. ``Description:`` / ``Bandwidth:`` etc. are key-value lines
    that don't start with an interface keyword and so are correctly kept
    inside the same block.
    """
    results = []
    if not raw:
        return results

    iface_header_re = re.compile(
        r"^(FortyGigE|FortyGige|HundredGigE|HundredGige|"
        r"Ten-GigabitEthernet|"
        r"M-GigabitEthernet|"
        r"GigabitEthernet|"
        r"FastEthernet|"
        r"XGE|FGE|HGE|MGE|GE|FE|"
        r"Bridge-Aggregation|Route-Aggregation|BAGG|RAGG)"
        r"[A-Za-z0-9/:.\-]+",
        re.IGNORECASE,
    )

    # Find every line-start position that begins with an interface header,
    # then slice the raw text between consecutive positions.
    lines = raw.splitlines(keepends=True)
    starts = []
    pos = 0
    for ln in lines:
        if iface_header_re.match(ln):
            starts.append(pos)
        pos += len(ln)
    starts.append(len(raw))  # sentinel

    blocks = []
    for i in range(len(starts) - 1):
        blocks.append(raw[starts[i]:starts[i+1]])

    DESC_NONE_TOKENS = {"", "--", "<none>", "none"}

    for block in blocks:
        first_line = block.splitlines()[0].strip()
        # Header line is just the interface name, optionally with a colon
        iface_name = first_line.split()[0].rstrip(":")

        # Link state
        link_state = ""
        m = re.search(r"(?:Current state|Line protocol (?:current )?state):\s*(\S+)", block)
        if m:
            link_state = m.group(1).upper()

        # Extract the Input/Output (total) sub-section so counter regex
        # doesn't match the "Last 300 seconds input rate" line.
        def _section(name: str) -> str:
            mm = re.search(
                rf"{name}\s*\(total\):(.*?)(?=^\S|\Z)",
                block, re.DOTALL | re.MULTILINE,
            )
            return mm.group(1) if mm else ""

        def _grab(text: str, patterns: list[str]) -> int:
            for pat in patterns:
                mm = re.search(pat, text, re.IGNORECASE)
                if mm:
                    return int(mm.group(1).replace(",", ""))
            return 0

        in_section  = _section("Input")
        out_section = _section("Output")

        in_packets    = _grab(in_section,  [r"([\d,]+)\s*packets"])
        in_bytes      = _grab(in_section,  [r"([\d,]+)\s*bytes"])
        in_broadcasts = _grab(in_section,  [r"([\d,]+)\s*broadcasts?"])
        in_errors     = _grab(in_section,  [r"([\d,]+)\s*input\s*errors?", r"([\d,]+)\s*errors?"])

        out_packets    = _grab(out_section, [r"([\d,]+)\s*packets"])
        out_bytes      = _grab(out_section, [r"([\d,]+)\s*bytes"])
        out_broadcasts = _grab(out_section, [r"([\d,]+)\s*broadcasts?"])
        out_errors     = _grab(out_section, [r"([\d,]+)\s*output\s*errors?", r"([\d,]+)\s*errors?"])

        # Description / mode / vlan
        description = ""
        m = re.search(r"^Description:\s*(.+?)\s*$", block, re.M)
        if m:
            v = m.group(1).strip()
            if v.lower() not in DESC_NONE_TOKENS:
                description = v

        mode = ""
        m = re.search(r"Port link-type:\s*(\S+)", block, re.I)
        if m:
            mode = m.group(1).strip().lower()

        vlan = ""
        m = re.search(r"PVID:\s*(\d+)", block)
        if m:
            vlan = m.group(1)

        parts = []
        if mode:        parts.append(mode)
        if vlan:        parts.append(f"vlan {vlan}")
        if description: parts.append(description)
        consolidated = " · ".join(parts)

        results.append({
            "interface_name": iface_name,
            "link_state":     link_state,
            "in_packets":     in_packets,
            "in_bytes":       in_bytes,
            "in_errors":      in_errors,
            "in_broadcasts":  in_broadcasts,
            "out_packets":    out_packets,
            "out_bytes":      out_bytes,
            "out_errors":     out_errors,
            "out_broadcasts": out_broadcasts,
            "total_packets":  in_packets + out_packets,
            "port_description": consolidated,
        })
    return results


# ─────────────────────────────────────────────────────────────────────
# ArubaOS-CX — `show interface statistics`  (NEW, tabular)
# ─────────────────────────────────────────────────────────────────────
#
# Expected output:
#
#   Interface     RX Bytes        RX Packets   RX Drops   TX Bytes        TX Packets   TX Drops   RX Broadcast   RX Multicast   TX Broadcast   TX Multicast   RX Pause   TX Pause
#   -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#   1/1/1 - lag123   4632840940508   4174300461   0          2512268789005   2677854560   0          189335254      356149681      376904470      272855343      0          0
#   1/1/5            12345           98           0          87              54           0          1              2              0              0              0          0
#
# Notes:
#   - Some rows have an inline " - lagN" annotation showing LAG membership;
#     we strip that and store only the physical interface name.
#   - 12 numeric columns always come in a fixed order on AOS-CX.
_AOSCX_STATS_COLUMNS = (
    "rx_bytes", "rx_packets", "rx_drops",
    "tx_bytes", "tx_packets", "tx_drops",
    "rx_broadcast", "rx_multicast",
    "tx_broadcast", "tx_multicast",
    "rx_pause", "tx_pause",
)

# Match a port identifier like "1/1/1" or "1/1/49:4" (split breakout port)
_AOSCX_IFACE_RE = re.compile(r"^\d+/\d+/\d+(?::\d+)?$")


def parse_aoscx_interface_statistics(raw: str) -> list[dict]:
    """
    Parse ArubaOS-CX `show interface statistics` (tabular) output.

    Robust to:
      - the optional " - lagN" trunk-membership annotation in column 1
      - extra blank lines, header banner, separator lines
      - breakout sub-ports (e.g. "1/1/49:4")
    """
    results = []

    if not raw:
        return results

    for line in raw.splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith(("Interface", "---", "===")):
            continue

        tokens = line.split()
        if not tokens:
            continue

        if not _AOSCX_IFACE_RE.match(tokens[0]):
            continue

        iface_name = tokens[0]

        # Strip the " - lagN" annotation if present:
        #   tokens = ["1/1/1", "-", "lag123", <12 numbers>]
        if len(tokens) >= 3 and tokens[1] == "-" and tokens[2].lower().startswith("lag"):
            numeric_tokens = tokens[3:]
        else:
            numeric_tokens = tokens[1:]

        if len(numeric_tokens) != len(_AOSCX_STATS_COLUMNS):
            # Malformed or output drift — skip rather than write bad data.
            continue

        try:
            values = [int(t.replace(",", "")) for t in numeric_tokens]
        except ValueError:
            continue

        cols = dict(zip(_AOSCX_STATS_COLUMNS, values))

        in_packets  = cols["rx_packets"]
        out_packets = cols["tx_packets"]

        results.append({
            "interface_name": iface_name,
            "link_state":     "",                    # not reported by this command
            "in_packets":     in_packets,
            "in_bytes":       cols["rx_bytes"],
            "in_errors":      cols["rx_drops"],     # closest semantic match
            "in_broadcasts":  cols["rx_broadcast"],
            "out_packets":    out_packets,
            "out_bytes":      cols["tx_bytes"],
            "out_errors":     cols["tx_drops"],
            "out_broadcasts": cols["tx_broadcast"],
            "total_packets":  in_packets + out_packets,
        })

    return results


# ─────────────────────────────────────────────────────────────────────
# ArubaOS-CX — `show interface`  (LEGACY verbose-block parser, kept)
# ─────────────────────────────────────────────────────────────────────
def parse_aoscx_interface_detail(raw: str) -> list[dict]:
    """Parse ArubaOS-CX verbose `show interface` output (per-interface block)."""
    results = []
    blocks = re.split(r"\n(?=Interface\s+\S+\s+is\s+)", raw)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        m = re.match(r"Interface\s+(\S+)\s+is\s+(\w+)", block)
        if not m:
            continue

        iface_name = m.group(1)
        link_state = m.group(2).upper()

        def num(pattern: str, text: str) -> int:
            mm = re.search(pattern, text)
            return int(mm.group(1).replace(",", "")) if mm else 0

        rx_section = re.search(r"\nRX\b(.*?)(?=\nTX\b|\Z)", block, re.S)
        tx_section = re.search(r"\nTX\b(.*?)\Z", block, re.S)
        rx_text = rx_section.group(1) if rx_section else ""
        tx_text = tx_section.group(1) if tx_section else ""

        in_ucast  = num(r"ucast:\s*([\d,]+)", rx_text)
        in_mcast  = num(r"mcast:\s*([\d,]+)", rx_text)
        in_bcast  = num(r"bcast:\s*([\d,]+)", rx_text)
        in_bytes  = num(r"Bytes:\s*([\d,]+)", rx_text)
        in_errors = num(r"Total Rx Errors:\s*([\d,]+)", rx_text)

        out_ucast  = num(r"ucast:\s*([\d,]+)", tx_text)
        out_mcast  = num(r"mcast:\s*([\d,]+)", tx_text)
        out_bcast  = num(r"bcast:\s*([\d,]+)", tx_text)
        out_bytes  = num(r"Bytes:\s*([\d,]+)", tx_text)
        out_errors = num(r"Total Tx Errors:\s*([\d,]+)", tx_text)

        in_packets  = in_ucast + in_mcast + in_bcast
        out_packets = out_ucast + out_mcast + out_bcast

        results.append({
            "interface_name": iface_name,
            "link_state":     link_state,
            "in_packets":     in_packets,
            "in_bytes":       in_bytes,
            "in_errors":      in_errors,
            "in_broadcasts":  in_bcast,
            "out_packets":    out_packets,
            "out_bytes":      out_bytes,
            "out_errors":     out_errors,
            "out_broadcasts": out_bcast,
            "total_packets":  in_packets + out_packets,
        })

    return results


# ─────────────────────────────────────────────────────────────────────
# ArubaOS-Switch (ProVision) — `show interfaces <port>`
# ─────────────────────────────────────────────────────────────────────
def parse_aruba_provision_interface_detail(raw: str) -> list[dict]:
    """Parse ArubaOS-Switch (ProVision) per-port `show interfaces` blocks."""
    results = []
    blocks = re.split(r"\n(?=Status and Counters - Port Counters for port )", raw)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        m = re.match(r"Status and Counters - Port Counters for port (\S+)", block)
        if not m:
            continue

        iface_name = m.group(1)

        link_state = ""
        lm = re.search(r"Link Status\s*:\s*(\w+)", block)
        if lm:
            link_state = lm.group(1).upper()

        def num(pattern: str, text: str) -> int:
            mm = re.search(pattern, text)
            return int(mm.group(1).replace(",", "")) if mm else 0

        in_bytes       = num(r"Bytes Rx\s*:\s*([\d,]+)", block)
        out_bytes      = num(r"Bytes Tx\s*:\s*([\d,]+)", block)
        in_unicast     = num(r"Unicast Rx\s*:\s*([\d,]+)", block)
        out_unicast    = num(r"Unicast Tx\s*:\s*([\d,]+)", block)
        in_bcastmcast  = num(r"Bcast/Mcast Rx\s*:\s*([\d,]+)", block)
        out_bcastmcast = num(r"Bcast/Mcast Tx\s*:\s*([\d,]+)", block)
        in_errors      = num(r"FCS Rx\s*:\s*([\d,]+)", block)
        out_errors     = num(r"Drops Tx\s*:\s*([\d,]+)", block)

        in_packets  = in_unicast + in_bcastmcast
        out_packets = out_unicast + out_bcastmcast

        results.append({
            "interface_name": iface_name,
            "link_state":     link_state,
            "in_packets":     in_packets,
            "in_bytes":       in_bytes,
            "in_errors":      in_errors,
            "in_broadcasts":  in_bcastmcast,
            "out_packets":    out_packets,
            "out_bytes":      out_bytes,
            "out_errors":     out_errors,
            "out_broadcasts": out_bcastmcast,
            "total_packets":  in_packets + out_packets,
        })

    return results


# ─────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────
#
# device_type -> (command_string, parser_fn)
#
# AOS-CX uses `show interface statistics` (tabular). The legacy verbose-block
# parser is still available under "aruba_aoscx_verbose" if a switch is set up
# to return that older format instead.
INTERFACE_PARSERS = {
    "hp_comware":           ("display interface",          parse_comware_interface_detail),
    "huawei":               ("display interface",          parse_comware_interface_detail),
    "huawei_vrp":           ("display interface",          parse_comware_interface_detail),

    "aruba_aoscx":          ("show interface statistics",  parse_aoscx_interface_statistics),
    "aruba_aoscx_verbose":  ("show interface",             parse_aoscx_interface_detail),

    "aruba_os":             ("show interface statistics",  parse_aoscx_interface_statistics),
    "aruba_osswitch":       ("show interface statistics",  parse_aoscx_interface_statistics),

    "aruba_procurve":       ("show interfaces",            parse_aruba_provision_interface_detail),
}


def get_interface_command_and_parser(device_type: str):
    """Return (command_string, parser_fn) for a device_type,
    falling back to Comware if unrecognized."""
    return INTERFACE_PARSERS.get(
        device_type, ("display interface", parse_comware_interface_detail)
    )


# ═════════════════════════════════════════════════════════════════════
# Brief-interface parsers — return {interface_name: {description, mode, vlan}}
# These pair with the verbose statistics parsers above. The scheduler
# captures the "brief" output too, and we merge `description`/`mode` into
# each PortStat row at insert time.
# ═════════════════════════════════════════════════════════════════════

def parse_comware_interface_brief(raw: str) -> dict:
    """Parse Comware `display interface brief` output.

    Sample:
        Interface            Link Protocol Primary IP      Description
        FGE1/0/53            UP   UP       10.25.241.86    CONNECTED-TO-CORE1-P23
        Ten-GigabitEthernet1/0/1 UP UP    --              SERVER-RACK-A
    """
    out = {}
    if not raw:
        return out

    in_table = False
    desc_col = None  # column position where Description starts (0-indexed)
    for line in raw.splitlines():
        # Find the header row first to learn description column position
        if "Interface" in line and "Link" in line and "Protocol" in line:
            in_table = True
            idx = line.find("Description")
            if idx > 0:
                desc_col = idx
            continue
        if not in_table:
            continue

        if not line.strip() or line.lstrip().startswith(("Link:", "Protocol:")):
            continue

        # Use column slicing for description (Comware right-pads consistently)
        if desc_col is not None and len(line) > desc_col:
            desc = line[desc_col:].strip()
        else:
            desc = ""

        tokens = line.split()
        if not tokens:
            continue
        iface = tokens[0]
        # Reject obvious non-interface lines
        if iface in ("Brief", "Link:", "Protocol:"):
            continue

        out[iface] = {
            "description": desc,
            "mode":        "",          # Comware brief doesn't show mode
            "vlan":        "",
        }
    return out


def parse_aoscx_interface_brief(raw: str) -> dict:
    """Parse ArubaOS-CX / AOS-S `show interface brief` output.

    Token layout per row:
      port  vlan  mode  type  enabled  status  [reason words...]  speed  [description words...]

    `reason` may be multi-word (e.g. "No XCVR installed") on down ports.
    `description` may be multi-word (e.g. "Connected To GCC-CORE-01-P5").
    `speed` is the anchor: it's the last purely-numeric token (or the
    `--` immediately before a final `--`), and everything after it is
    the description.
    """
    out = {}
    if not raw:
        return out

    headers_found = False
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if ("Port" in line or "Interface" in line) and "Mode" in line:
            headers_found = True
            continue
        if not headers_found:
            continue
        if s.startswith("---") or s.startswith("==="):
            continue

        tokens = line.split()
        if len(tokens) < 6:
            continue

        port = tokens[0]
        vlan_tok = tokens[1]
        mode_tok = tokens[2].lower() if len(tokens) >= 3 else ""

        vlan = vlan_tok if vlan_tok != "--" else ""
        mode = mode_tok if mode_tok in ("trunk", "access", "routed", "hybrid") else ""

        # Anchor on speed (rightmost pure-numeric token, with the special
        # case that "speed=--, description=--" appears as two trailing dashes).
        speed_idx = None
        for i in range(len(tokens) - 1, 1, -1):
            t = tokens[i]
            if t.isdigit():
                speed_idx = i
                break
            if t == "--" and i == len(tokens) - 1 and i > 0:
                prev = tokens[i - 1]
                if prev.isdigit() or prev == "--":
                    speed_idx = i - 1
                    break

        if speed_idx is None:
            continue

        desc_tokens = tokens[speed_idx + 1:]
        description = " ".join(desc_tokens).strip()
        if description == "--":
            description = ""

        out[port] = {
            "description": description,
            "mode":        mode,
            "vlan":        vlan,
        }
    return out


# ═════════════════════════════════════════════════════════════════════
# Brief command dispatch — { device_type: (command, parser_fn) }
# ═════════════════════════════════════════════════════════════════════

BRIEF_PARSERS = {
    "hp_comware":     ("display interface brief",  parse_comware_interface_brief),
    "huawei":         ("display interface brief",  parse_comware_interface_brief),
    "huawei_vrp":     ("display interface brief",  parse_comware_interface_brief),
    "aruba_aoscx":    ("show interface brief",     parse_aoscx_interface_brief),
    "aruba_os":       ("show interface brief",     parse_aoscx_interface_brief),
    "aruba_osswitch": ("show interface brief",     parse_aoscx_interface_brief),
    "aruba_procurve": ("show interfaces brief",    parse_aoscx_interface_brief),
}


def get_brief_command_and_parser(device_type: str):
    return BRIEF_PARSERS.get(
        device_type, ("display interface brief", parse_comware_interface_brief)
    )


_COMWARE_NAME_SHORT_FORMS = [
    (re.compile(r"^FortyGigE",         re.I), "FGE"),
    (re.compile(r"^HundredGigE",       re.I), "HGE"),
    (re.compile(r"^Ten-GigabitEthernet", re.I), "XGE"),
    (re.compile(r"^M-GigabitEthernet", re.I), "MGE"),
    (re.compile(r"^GigabitEthernet",   re.I), "GE"),
    (re.compile(r"^FastEthernet",      re.I), "FE"),
    (re.compile(r"^Bridge-Aggregation",re.I), "BAGG"),
    (re.compile(r"^Route-Aggregation", re.I), "RAGG"),
]


def normalize_comware_name(name: str) -> str:
    """Map any of the long Comware interface names to its abbreviated form
    (``FortyGigE1/0/52`` → ``FGE1/0/52``) so a name from
    ``display interface`` can be looked up against a brief that uses the
    short form, and vice-versa.  Idempotent — names already in short form
    pass through unchanged."""
    if not name:
        return name
    for pattern, short in _COMWARE_NAME_SHORT_FORMS:
        if pattern.match(name):
            return pattern.sub(short, name, count=1)
    return name


def merge_brief_into_stats(stats_rows: list, brief_map: dict) -> list:
    """For each row in `stats_rows`, look up its interface in `brief_map`
    and write a SINGLE consolidated descriptor into `port_description`.

    Lookup is name-tolerant: tries the row's interface name as-is AND its
    Comware-abbreviated form so ``FortyGigE1/0/52`` will still find
    ``FGE1/0/52`` in the brief.

    Will NOT overwrite a port_description the verbose parser already
    extracted directly — the verbose path is preferred when available.
    """
    # Build a brief_map keyed by BOTH the original and the short form
    expanded = {}
    for key, info in (brief_map or {}).items():
        expanded[key] = info
        expanded[normalize_comware_name(key)] = info

    for row in stats_rows:
        # Already populated by the verbose parser → leave it alone
        if row.get("port_description"):
            continue

        name = row["interface_name"]
        info = expanded.get(name) or expanded.get(normalize_comware_name(name)) or {}
        parts = []
        if info.get("mode"):        parts.append(info["mode"])
        if info.get("vlan"):        parts.append(f"vlan {info['vlan']}")
        if info.get("description"): parts.append(info["description"])
        row["port_description"] = " · ".join(parts)
    return stats_rows