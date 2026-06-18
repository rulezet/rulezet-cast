"""formats_manifest.py — Static display metadata for all registered formats.

Canonical source of truth for icon, color, description and execution flags.
Keyed by parser.format (lowercase). Used by engine.list_parsers() and external
tools (e.g. Rulezet) to seed/update their format registry.
"""

FORMAT_METADATA: dict = {
    'yara': {
        'display_name':   'YARA',
        'description':    'YARA malware detection rules — pattern matching for files and processes.',
        'icon':           'fa-shield-halved',
        'color':          '#FF6B2B',
        'file_extension': 'yar',
        'can_be_executed': True,
    },
    'sigma': {
        'display_name':   'Sigma',
        'description':    'Generic SIEM detection signatures — vendor-agnostic log search rules.',
        'icon':           'fa-chart-simple',
        'color':          '#0078D4',
        'file_extension': 'yml',
        'can_be_executed': False,
    },
    'suricata': {
        'display_name':   'Suricata',
        'description':    'Suricata IDS/IPS network traffic detection rules.',
        'icon':           'fa-fish',
        'color':          '#F4A300',
        'file_extension': 'rules',
        'can_be_executed': True,
    },
    'crs': {
        'display_name':   'CRS',
        'description':    'OWASP Core Rule Set — ModSecurity WAF detection rules.',
        'icon':           'fa-shield-cat',
        'color':          '#E53935',
        'file_extension': 'conf',
        'can_be_executed': False,
    },
    'nse': {
        'display_name':   'NSE',
        'description':    'Nmap Scripting Engine — Lua-based network service probes.',
        'icon':           'fa-network-wired',
        'color':          '#8BC34A',
        'file_extension': 'nse',
        'can_be_executed': True,
    },
    'nova': {
        'display_name':   'Nova',
        'description':    'Nova AI/LLM hunting rules for detecting adversarial AI behaviour.',
        'icon':           'fa-robot',
        'color':          '#AB47BC',
        'file_extension': 'nov',
        'can_be_executed': False,
    },
    'zeek': {
        'display_name':   'Zeek',
        'description':    'Zeek (formerly Bro) network analysis and detection scripts.',
        'icon':           'fa-magnifying-glass',
        'color':          '#00ACC1',
        'file_extension': 'zeek',
        'can_be_executed': True,
    },
    'wazuh': {
        'display_name':   'Wazuh',
        'description':    'Wazuh SIEM/XDR detection rules in XML format.',
        'icon':           'fa-server',
        'color':          '#00C853',
        'file_extension': 'xml',
        'can_be_executed': False,
    },
    'elastic': {
        'display_name':   'Elastic',
        'description':    'Elastic Security detection rules in TOML format.',
        'icon':           'fa-bolt',
        'color':          '#FDD835',
        'file_extension': 'toml',
        'can_be_executed': False,
    },
    'atr': {
        'display_name':   'ATR',
        'description':    'Agent Threat Rules — structured threat intelligence for AI agents.',
        'icon':           'fa-brain',
        'color':          '#FF7043',
        'file_extension': 'yaml',
        'can_be_executed': False,
    },
}
