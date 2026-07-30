"""
bulk_import.py — Turn an uploaded spreadsheet into a list of servers to add.

WHY THIS EXISTS
---------------
The bundled iLO catalogue covers the machines we already knew about. When a
team hands over a rack, the list arrives as a spreadsheet — and typing forty
addresses into the manual form one at a time is exactly the kind of work this
portal is supposed to remove.

WHAT IT ACCEPTS
---------------
CSV (.csv, .tsv, .txt) or Excel (.xlsx, .xlsm). Column headers are matched
loosely and case-insensitively, because real spreadsheets are never tidy:

    iLO address   ilo_ip · ilo ip · ilo · ip · address · host · ilo_address
    Name          name · hostname · server · server_name · node
    Username      username · user · ilo_user · login
    Password      password · pass · ilo_password
    Location      location · rack · site · datacenter
    Description   description · model · notes · comment · remarks

Only the iLO address is required. Anything else is optional: a row without a
username falls back to the credentials typed once in the dialog, and a row
without a name is named from the bundled catalogue or from its address.

A file with NO recognisable header row is also accepted — if the first cell
of the first row looks like an IP or hostname, every row is treated as a bare
address list. That covers the common "someone pasted a column of IPs" case.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not touch the database and it does not contact any device. It parses,
validates, and reports. The caller decides what to do with the result, which
is what lets the UI show a preview before anything is added.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re

# ── header synonyms ────────────────────────────────────────────────────────
_FIELD_SYNONYMS = {
    "ilo_ip": ("ilo_ip", "ilo ip", "iloip", "ilo", "ilo_address", "ilo address",
               "ip", "ip address", "ipaddress", "address", "host", "hostname/ip",
               "management ip", "mgmt ip", "bmc", "bmc ip"),
    "name": ("name", "hostname", "host name", "server", "server name",
             "server_name", "node", "node name", "label"),
    "username": ("username", "user", "user name", "ilo_user", "ilo user",
                 "login", "account"),
    "password": ("password", "pass", "passwd", "ilo_password", "ilo password",
                 "secret"),
    "location": ("location", "rack", "site", "datacenter", "data centre",
                 "data center", "room"),
    "description": ("description", "desc", "model", "notes", "note", "comment",
                    "comments", "remarks", "details", "purpose"),
}

# Hostname is deliberately permissive but must not match a stray word like
# "Rack" — it needs a dot or a digit to look like an actual address.
_HOSTNAME_RE = re.compile(r"^(?=.*[.\d])[A-Za-z0-9][A-Za-z0-9.\-]{1,252}$")


class BulkParseError(Exception):
    """Raised when the file cannot be read at all (bad format, empty, no IPs)."""


def _norm_header(h) -> str:
    return re.sub(r"[\s_\-]+", " ", str(h or "").strip().lower())


def _looks_like_address(v: str) -> bool:
    v = (v or "").strip()
    if not v:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(v)) and "." in v


def _map_columns(header_row: list) -> dict:
    """Return {field: column_index} for whatever we recognise."""
    mapping = {}
    for idx, cell in enumerate(header_row):
        norm = _norm_header(cell)
        if not norm:
            continue
        for field, synonyms in _FIELD_SYNONYMS.items():
            if field in mapping:
                continue
            if norm in synonyms:
                mapping[field] = idx
                break
    return mapping


def _read_csv(data: bytes) -> list[list]:
    text = data.decode("utf-8-sig", errors="replace")
    # Sniff the delimiter so tab- and semicolon-separated exports work too.
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delim = dialect.delimiter
    except Exception:
        delim = "\t" if sample.count("\t") > sample.count(",") else ","
    return [row for row in csv.reader(io.StringIO(text), delimiter=delim)]


def _read_xlsx(data: bytes) -> list[list]:
    try:
        import openpyxl
    except ImportError as e:                     # pragma: no cover
        raise BulkParseError(
            "Excel support is not installed on the backend (openpyxl). "
            "Save the sheet as CSV and upload that instead.") from e
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True,
                                    data_only=True)
    except Exception as e:
        raise BulkParseError(f"could not read the Excel file: {e}") from e
    try:
        ws = wb[wb.sheetnames[0]]                # first sheet only
        rows = []
        for r in ws.iter_rows(values_only=True):
            rows.append(["" if c is None else str(c).strip() for c in r])
        return rows
    finally:
        wb.close()


def parse_file(filename: str, data: bytes) -> dict:
    """Parse an uploaded file into candidate server rows.

    Returns {"rows": [...], "warnings": [...], "columns_detected": {...},
             "had_header": bool}
    Each row: {ilo_ip, name, username, password, location, description,
               source_row}
    """
    if not data:
        raise BulkParseError("the uploaded file is empty")

    name_lower = (filename or "").lower()
    if name_lower.endswith((".xlsx", ".xlsm")):
        table = _read_xlsx(data)
    elif name_lower.endswith((".csv", ".tsv", ".txt")):
        table = _read_csv(data)
    elif name_lower.endswith(".xls"):
        raise BulkParseError(
            "legacy .xls files are not supported — re-save as .xlsx or .csv")
    else:
        # No usable extension: try CSV, since that is the forgiving format.
        table = _read_csv(data)

    table = [r for r in table if any(str(c).strip() for c in r)]
    if not table:
        raise BulkParseError("the file has no rows")

    warnings: list[str] = []

    # ── decide whether row 0 is a header ──
    mapping = _map_columns(table[0])
    had_header = "ilo_ip" in mapping
    body = table[1:] if had_header else table

    if not had_header:
        # Headerless: find the column that actually holds addresses, so a
        # sheet with "Rack, IP, Owner" and no header still works.
        col = None
        for candidate in range(len(table[0])):
            hits = sum(1 for r in table[:20]
                       if len(r) > candidate and _looks_like_address(r[candidate]))
            if hits:
                col = candidate
                break
        if col is None:
            raise BulkParseError(
                "no iLO addresses found. Add a header row with a column named "
                "'iLO IP' (or 'ip' / 'host' / 'address'), or provide a single "
                "column of addresses.")
        mapping = {"ilo_ip": col}
        warnings.append(
            f"No header row recognised — treating column {col + 1} as the iLO "
            f"address and ignoring other columns.")

    def cell(row, field):
        idx = mapping.get(field)
        if idx is None or idx >= len(row):
            return ""
        return str(row[idx] or "").strip()

    rows, seen = [], set()
    for n, raw in enumerate(body, start=2 if had_header else 1):
        ip = cell(raw, "ilo_ip")
        if not ip:
            continue
        if not _looks_like_address(ip):
            warnings.append(f"Row {n}: '{ip}' is not a valid IP or hostname — skipped.")
            continue
        if ip in seen:
            warnings.append(f"Row {n}: {ip} appears more than once — kept the first.")
            continue
        seen.add(ip)
        rows.append({
            "ilo_ip": ip,
            "name": cell(raw, "name"),
            "username": cell(raw, "username"),
            "password": cell(raw, "password"),
            "location": cell(raw, "location"),
            "description": cell(raw, "description"),
            "source_row": n,
        })

    if not rows:
        raise BulkParseError(
            "no valid iLO addresses found in the file. Check that the address "
            "column contains IPs or hostnames.")

    detected = {f: (mapping[f] + 1) for f in mapping}     # 1-based for humans
    return {"rows": rows, "warnings": warnings,
            "columns_detected": detected, "had_header": had_header}
