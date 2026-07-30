"""
builtin_templates.py — starter configuration templates.

Seeded once into config_templates; fully editable afterwards. Each ships a
variable schema so the UI can render a typed form and validate before preview.

Phase 1 NEVER executes these. They exist to be rendered, reviewed and diffed.
"""

BUILTIN_TEMPLATES = [
    # ── Access port ────────────────────────────────────────────────────────
    {
        "name": "Access Port (Aruba AOS-CX)",
        "category": "port",
        "device_type": "aruba_aoscx",
        "description": "Untagged access port in a single VLAN, with a description.",
        "body": (
            "configure terminal\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  no shutdown\n"
            "  description {{ description }}\n"
            "  no routing\n"
            "  vlan access {{ access_vlan }}\n"
            "  exit\n"
            "{% endfor %}"
            "exit\n"
        ),
        "variables": [
            {"name": "ports", "type": "list", "required": True,
             "description": "Interfaces, comma separated (e.g. 1/1/5, 1/1/6)"},
            {"name": "access_vlan", "type": "vlan", "required": True,
             "description": "Untagged VLAN ID (1-4094)"},
            {"name": "description", "type": "string", "required": True,
             "description": "Port description / purpose"},
        ],
    },
    {
        "name": "Access Port (HP Comware)",
        "category": "port",
        "device_type": "hp_comware",
        "description": "Untagged access port in a single VLAN, with a description.",
        "body": (
            "system-view\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  undo shutdown\n"
            "  description {{ description }}\n"
            "  port link-type access\n"
            "  port access vlan {{ access_vlan }}\n"
            "  quit\n"
            "{% endfor %}"
            "quit\n"
        ),
        "variables": [
            {"name": "ports", "type": "list", "required": True,
             "description": "Interfaces, comma separated (e.g. GE1/0/5)"},
            {"name": "access_vlan", "type": "vlan", "required": True,
             "description": "Untagged VLAN ID (1-4094)"},
            {"name": "description", "type": "string", "required": True,
             "description": "Port description / purpose"},
        ],
    },

    # ── Trunk port ─────────────────────────────────────────────────────────
    {
        "name": "Trunk Port (Aruba AOS-CX)",
        "category": "port",
        "device_type": "aruba_aoscx",
        "description": "802.1Q trunk carrying a set of tagged VLANs plus a native VLAN.",
        "body": (
            "configure terminal\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  no shutdown\n"
            "  description {{ description }}\n"
            "  no routing\n"
            "  vlan trunk native {{ native_vlan }}\n"
            "  vlan trunk allowed {{ allowed_vlans }}\n"
            "  exit\n"
            "{% endfor %}"
            "exit\n"
        ),
        "variables": [
            {"name": "ports", "type": "list", "required": True,
             "description": "Trunk interfaces, comma separated"},
            {"name": "native_vlan", "type": "vlan", "required": True,
             "description": "Untagged / native VLAN"},
            {"name": "allowed_vlans", "type": "string", "required": True,
             "description": "Tagged VLANs, e.g. 10,20,246-248"},
            {"name": "description", "type": "string", "required": True,
             "description": "Trunk description"},
        ],
    },
    {
        "name": "Trunk Port (HP Comware)",
        "category": "port",
        "device_type": "hp_comware",
        "description": "802.1Q trunk carrying a set of tagged VLANs plus a PVID.",
        "body": (
            "system-view\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  undo shutdown\n"
            "  description {{ description }}\n"
            "  port link-type trunk\n"
            "  port trunk pvid vlan {{ native_vlan }}\n"
            "  port trunk permit vlan {{ allowed_vlans }}\n"
            "  quit\n"
            "{% endfor %}"
            "quit\n"
        ),
        "variables": [
            {"name": "ports", "type": "list", "required": True,
             "description": "Trunk interfaces, comma separated"},
            {"name": "native_vlan", "type": "vlan", "required": True,
             "description": "PVID / native VLAN"},
            {"name": "allowed_vlans", "type": "string", "required": True,
             "description": "Permitted VLANs, e.g. 10 20 246 to 248"},
            {"name": "description", "type": "string", "required": True,
             "description": "Trunk description"},
        ],
    },

    # ── Server LACP ────────────────────────────────────────────────────────
    {
        "name": "Server LACP (Aruba AOS-CX)",
        "category": "uplink",
        "device_type": "aruba_aoscx",
        "description": (
            "Dual-homed server bond: creates a LAG, sets LACP active, and "
            "adds the member interfaces."
        ),
        "body": (
            "configure terminal\n"
            "interface lag {{ lag_id }}\n"
            "  no shutdown\n"
            "  description {{ description }}\n"
            "  no routing\n"
            "  vlan access {{ access_vlan }}\n"
            "  lacp mode active\n"
            "  exit\n"
            "{% for p in member_ports %}"
            "interface {{ p }}\n"
            "  no shutdown\n"
            "  description {{ description }} member\n"
            "  lag {{ lag_id }}\n"
            "  exit\n"
            "{% endfor %}"
            "exit\n"
        ),
        "variables": [
            {"name": "lag_id", "type": "int", "required": True,
             "description": "LAG identifier (e.g. 12)"},
            {"name": "member_ports", "type": "list", "required": True,
             "description": "Member interfaces, comma separated (e.g. 1/1/3, 1/1/4)"},
            {"name": "access_vlan", "type": "vlan", "required": True,
             "description": "VLAN the bond carries"},
            {"name": "description", "type": "string", "required": True,
             "description": "Server name / purpose"},
        ],
    },
    {
        "name": "Server LACP (HP Comware)",
        "category": "uplink",
        "device_type": "hp_comware",
        "description": (
            "Dual-homed server bond: creates a Bridge-Aggregation interface "
            "in dynamic (LACP) mode and binds the member ports."
        ),
        "body": (
            "system-view\n"
            "interface Bridge-Aggregation {{ lag_id }}\n"
            "  description {{ description }}\n"
            "  link-aggregation mode dynamic\n"
            "  port link-type access\n"
            "  port access vlan {{ access_vlan }}\n"
            "  quit\n"
            "{% for p in member_ports %}"
            "interface {{ p }}\n"
            "  undo shutdown\n"
            "  description {{ description }} member\n"
            "  port link-aggregation group {{ lag_id }}\n"
            "  quit\n"
            "{% endfor %}"
            "quit\n"
        ),
        "variables": [
            {"name": "lag_id", "type": "int", "required": True,
             "description": "Bridge-Aggregation number (e.g. 12)"},
            {"name": "member_ports", "type": "list", "required": True,
             "description": "Member interfaces, comma separated"},
            {"name": "access_vlan", "type": "vlan", "required": True,
             "description": "VLAN the bond carries"},
            {"name": "description", "type": "string", "required": True,
             "description": "Server name / purpose"},
        ],
    },

    # ── General-purpose LACP port-channel (used by the LACP tab) ─────────
    # Unlike "Server LACP" these do NOT touch VLAN membership: they only
    # create the aggregate and bind the selected member ports. L2 config on
    # the LAG (access/trunk) is a separate, reviewable change.
    {
        "name": "LACP Port-Channel (Aruba AOS-CX)",
        "category": "lacp",
        "device_type": "aruba_aoscx",
        "description": (
            "Creates a LAG interface running LACP and binds the selected "
            "member ports to it. VLAN/trunk settings on the LAG are left at "
            "defaults — apply an access/trunk template to the LAG afterwards."
        ),
        "body": (
            "configure terminal\n"
            "interface lag {{ lag_id }}\n"
            "  no shutdown\n"
            "  description {{ description }}\n"
            "  no routing\n"
            "  lacp mode {{ lacp_mode }}\n"
            "  exit\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  no shutdown\n"
            "  lag {{ lag_id }}\n"
            "  exit\n"
            "{% endfor %}"
            "exit\n"
        ),
        "variables": [
            {"name": "lag_id", "type": "int", "required": True,
             "description": "LAG number (e.g. 10)"},
            {"name": "ports", "type": "list", "required": True,
             "description": "Member interfaces, comma separated (e.g. 1/1/5, 1/1/6)"},
            {"name": "lacp_mode", "type": "string", "required": True,
             "choices": ["active", "passive"],
             "description": "LACP negotiation mode (at least one side must be active)"},
            {"name": "description", "type": "string", "required": True,
             "description": "Purpose of the bond (e.g. uplink to core-2)"},
        ],
    },
    {
        "name": "LACP Port-Channel (HP Comware)",
        "category": "lacp",
        "device_type": "hp_comware",
        "description": (
            "Creates a Bridge-Aggregation in dynamic (LACP) mode and binds the "
            "selected member ports. The aggregation mode is set BEFORE members "
            "join (Comware refuses a mode change on a group with members). "
            "Member ports must not carry conflicting port-level config, or the "
            "device rejects the join."
        ),
        "body": (
            "system-view\n"
            "interface Bridge-Aggregation {{ lag_id }}\n"
            "  description {{ description }}\n"
            "  link-aggregation mode dynamic\n"
            "  quit\n"
            "{% for p in ports %}"
            "interface {{ p }}\n"
            "  port link-aggregation group {{ lag_id }}\n"
            "  quit\n"
            "{% endfor %}"
            "quit\n"
        ),
        "variables": [
            {"name": "lag_id", "type": "int", "required": True,
             "description": "Bridge-Aggregation number (e.g. 10)"},
            {"name": "ports", "type": "list", "required": True,
             "description": "Member interfaces, comma separated (e.g. GE1/0/5, GE1/0/6)"},
            {"name": "description", "type": "string", "required": True,
             "description": "Purpose of the bond (e.g. uplink to core-2)"},
        ],
    },
]


def seed_builtin_templates(db, models, json) -> int:
    """Insert the starter templates once. Returns how many were added."""
    added = 0
    for t in BUILTIN_TEMPLATES:
        exists = (db.query(models.ConfigTemplate)
                  .filter(models.ConfigTemplate.name == t["name"]).first())
        if exists:
            continue
        db.add(models.ConfigTemplate(
            name=t["name"], category=t["category"],
            device_type=t["device_type"], description=t["description"],
            body=t["body"], variables=json.dumps(t["variables"]),
            builtin=True, created_by="system",
        ))
        added += 1
    if added:
        db.commit()
    return added
