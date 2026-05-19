# ============================================================
# RULECAST — ZEEK TEST SUITE
#
# EXPECTED RESULTS (update when adding rules):
#   Total rules  : 6
#   Valid        : 4
#   Invalid      : 2
#
# Run with: python3 main.py test → choose zeek → file
# ============================================================
#
# Split boundary: each script starts with 'module Name;'
# identity.name = module name → must start with Valid_/Invalid_/Nasty_
# ============================================================


# ============================================================
# VALID RULES
# Must pass validate(). identity.name must start with "Valid_"
# ============================================================

##! Detects SSH brute-force login attempts by tracking repeated failures.
## Raises a notice when the failure count exceeds the threshold.
## @author CIRCL
## @version 1.0

module Valid_SSHBruteforce;

@load base/frameworks/notice
@load base/protocols/ssh

export {
    redef enum Notice::Type += {
        SSH_Bruteforce_Detected,
    };
    const brute_threshold: count = 10 &redef;
}

global ssh_failures: table[addr] of count &default=0;

event ssh_auth_failed(c: connection, authenticated: bool) {
    local src = c$id$orig_h;
    ++ssh_failures[src];
    if (ssh_failures[src] >= brute_threshold) {
        NOTICE([$note=SSH_Bruteforce_Detected,
                $conn=c,
                $msg=fmt("SSH brute-force from %s (%d failures)",
                         src, ssh_failures[src])]);
    }
}

event zeek_init() {
    print "SSH brute-force detector loaded";
}

##! Detects DNS tunneling by monitoring unusually long DNS query names.
## Long subdomains can indicate data exfiltration over DNS.
## CVE-2021-44228 may be delivered via DNS tunnels.
## @author CIRCL
## @version 1.2

module Valid_DNSTunnel;

@load base/frameworks/notice
@load base/protocols/dns

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Detected,
        DNS_Exfil_Suspected,
    };
    const dns_name_len_threshold: count = 50 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count) {
    if (|query| > dns_name_len_threshold) {
        NOTICE([$note=DNS_Tunnel_Detected,
                $conn=c,
                $msg=fmt("Suspiciously long DNS query (%d chars): %s",
                         |query|, query)]);
    }
}

event zeek_init() {
    print "DNS tunnel detector loaded";
}

##! Detects HTTP requests to known C2 beaconing patterns.
## Monitors periodic outbound HTTP connections with low variance.
## @author CIRCL
## @version 1.0

module Valid_C2Beacon;

@load base/frameworks/notice
@load base/protocols/http

export {
    redef enum Notice::Type += {
        C2_Beacon_Detected,
    };
}

global beacon_counts: table[addr] of count &default=0;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local src = c$id$orig_h;
    ++beacon_counts[src];
}

event zeek_done() {
    print "C2 beacon analysis complete";
}

##! Detects port scans by counting distinct destination ports per source.
## @author CIRCL
## @version 2.0

module Valid_PortScan;

@load base/frameworks/notice
@load base/protocols/conn

export {
    redef enum Notice::Type += {
        Port_Scan_Detected,
    };
    const scan_threshold: count = 25 &redef;
}

global scan_table: table[addr] of set[port] &create_expire=10 min;

event new_connection(c: connection) {
    local src  = c$id$orig_h;
    local dport = c$id$resp_p;
    if (src !in scan_table) {
        scan_table[src] = set();
    }
    add scan_table[src][dport];
    if (|scan_table[src]| > scan_threshold) {
        NOTICE([$note=Port_Scan_Detected,
                $src=src,
                $msg=fmt("Port scan detected from %s", src)]);
    }
}

event zeek_init() {
    print "Port scan detector loaded";
}


# ============================================================
# INVALID RULES
# Must fail validate(). identity.name must start with "Invalid_"
# ============================================================

##! Rule with syntax error: missing closing parenthesis in event handler.
## @author Test

module Invalid_SyntaxError;

@load base/frameworks/notice

event zeek_init( {
    print "this will not parse";
}

##! Rule with unclosed brace in export block.
## @author Test

module Invalid_UnclosedBrace;

@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        Bad_Notice,
    ;

event zeek_init() {
    print "bad";
}
