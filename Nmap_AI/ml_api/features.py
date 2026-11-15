"""
features.py - one place that turns network connections into model features.

Both training (train.py) and live scoring (scorer.py) use this file, so the
model always sees the same features in the same way.

We only use features that can be computed from a Zeek conn.log:
  * basic:  duration, protocol_type, service, flag, src_bytes, dst_bytes, land
  * time window (last 2 seconds):   count, srv_count, *_error_rate, *_srv_rate
  * host window (last 100 connections): dst_host_* features

NSL-KDD "content" features (hot, num_failed_logins, root_shell, ...) need the
packet payload, which conn.log does not have, so they are not used at all.
"""
from __future__ import annotations

import json
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Feature lists (the model is trained on exactly these columns, in this order)
# ---------------------------------------------------------------------------
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']

BASIC_NUMERIC = ['duration', 'src_bytes', 'dst_bytes', 'land']

TIME_WINDOW_FEATURES = [
    'count', 'srv_count',
    'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
]

HOST_WINDOW_FEATURES = [
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]

NUMERIC_FEATURES = BASIC_NUMERIC + TIME_WINDOW_FEATURES + HOST_WINDOW_FEATURES
ALL_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES

TIME_WINDOW_SECONDS = 2.0
HOST_WINDOW_CONNECTIONS = 100
# NSL-KDD caps these counters, so we cap them the same way.
MAX_TIME_COUNT = 511
MAX_HOST_COUNT = 255

# Zeek conn_state values that NSL-KDD counts as "SYN errors" and "REJ errors"
SYN_ERROR_STATES = {'S0', 'S1', 'S2', 'S3', 'SH'}
REJ_ERROR_STATES = {'REJ'}

# Plain-English meaning of each feature, used to explain alerts.
FEATURE_DESCRIPTIONS = {
    'protocol_type': 'Protocol',
    'service': 'Service',
    'flag': 'Connection state',
    'duration': 'Connection length (seconds)',
    'src_bytes': 'Bytes sent by the source',
    'dst_bytes': 'Bytes sent back by the destination',
    'land': 'Source and destination are the same host and port',
    'count': 'Connections to the same host in the last 2 seconds',
    'srv_count': 'Connections to the same service in the last 2 seconds',
    'serror_rate': 'Share of recent connections to this host that were half-open (SYN errors)',
    'srv_serror_rate': 'Share of recent connections to this service that were half-open (SYN errors)',
    'rerror_rate': 'Share of recent connections to this host that were rejected',
    'srv_rerror_rate': 'Share of recent connections to this service that were rejected',
    'same_srv_rate': 'Share of recent connections to this host that used the same service',
    'diff_srv_rate': 'Share of recent connections to this host that used different services',
    'srv_diff_host_rate': 'Share of recent connections to this service that went to different hosts',
    'dst_host_count': 'Connections to this host among the last 100',
    'dst_host_srv_count': 'Connections to this service among the last 100',
    'dst_host_same_srv_rate': 'Share of this host\'s last connections that used the same service',
    'dst_host_diff_srv_rate': 'Share of this host\'s last connections that used different services',
    'dst_host_same_src_port_rate': 'Share of this host\'s last connections from the same source port',
    'dst_host_srv_diff_host_rate': 'Share of this service\'s last connections that went to different hosts',
    'dst_host_serror_rate': 'Share of this host\'s last connections that were half-open (SYN errors)',
    'dst_host_srv_serror_rate': 'Share of this service\'s last connections that were half-open (SYN errors)',
    'dst_host_rerror_rate': 'Share of this host\'s last connections that were rejected',
    'dst_host_srv_rerror_rate': 'Share of this service\'s last connections that were rejected',
}

# ---------------------------------------------------------------------------
# Service names: NSL-KDD names services by port. Zeek names them by protocol
# detection. We map both to the NSL-KDD names.
# ---------------------------------------------------------------------------
TCP_PORT_SERVICES = {
    5: 'rje', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 15: 'netstat',
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 37: 'time',
    42: 'name', 43: 'whois', 53: 'domain', 57: 'mtp', 70: 'gopher', 79: 'finger',
    80: 'http', 84: 'ctf', 87: 'link', 95: 'supdup', 101: 'hostnames',
    102: 'iso_tsap', 105: 'csnet_ns', 109: 'pop_2', 110: 'pop_3', 111: 'sunrpc',
    113: 'auth', 117: 'uucp_path', 119: 'nntp', 137: 'netbios_ns',
    138: 'netbios_dgm', 139: 'netbios_ssn', 143: 'imap4', 150: 'sql_net',
    175: 'vmnet', 179: 'bgp', 194: 'IRC', 210: 'Z39_50', 389: 'ldap',
    443: 'http_443', 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer',
    520: 'efs', 530: 'courier', 540: 'uucp', 543: 'klogin', 544: 'kshell',
    2784: 'http_2784', 5190: 'aol', 8000: 'http', 8008: 'http', 8080: 'http',
    8001: 'http_8001', 6667: 'IRC',
}
UDP_PORT_SERVICES = {53: 'domain_u', 69: 'tftp_u', 123: 'ntp_u'}
ZEEK_SERVICE_TO_KDD = {
    'http': 'http', 'ssl': 'http_443', 'ftp': 'ftp', 'ftp-data': 'ftp_data',
    'ssh': 'ssh', 'smtp': 'smtp', 'pop3': 'pop_3', 'imap': 'imap4', 'irc': 'IRC',
    'ldap': 'ldap', 'telnet': 'telnet', 'finger': 'finger', 'ntp': 'ntp_u',
    'tftp': 'tftp_u', 'sunrpc': 'sunrpc', 'netbios-ns': 'netbios_ns',
    'netbios-ssn': 'netbios_ssn',
}
# ICMP: Zeek puts the ICMP type in id.orig_p
ICMP_TYPE_SERVICES = {0: 'ecr_i', 8: 'eco_i', 3: 'urp_i', 5: 'red_i', 13: 'tim_i', 14: 'tim_i'}


def _to_int(value, default=-1):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def kdd_service(proto: str, resp_port, orig_port, zeek_service) -> str:
    """Map one Zeek connection to an NSL-KDD service name."""
    proto = (proto or '').lower()
    if proto == 'icmp':
        return ICMP_TYPE_SERVICES.get(_to_int(orig_port), 'oth_i')
    port = _to_int(resp_port)
    if proto == 'tcp':
        if 6000 <= port <= 6063:
            return 'X11'
        if port in TCP_PORT_SERVICES:
            return TCP_PORT_SERVICES[port]
    elif proto == 'udp' and port in UDP_PORT_SERVICES:
        return UDP_PORT_SERVICES[port]
    # Port not known: fall back to what Zeek detected (first one if several)
    first = str(zeek_service or '').split(',')[0].strip().lower()
    if first == 'dns':
        return 'domain_u' if proto == 'udp' else 'domain'
    if first in ZEEK_SERVICE_TO_KDD:
        return ZEEK_SERVICE_TO_KDD[first]
    return 'private'


def kdd_flag(proto: str, conn_state) -> str:
    """Map a Zeek conn_state to an NSL-KDD flag.

    NSL-KDD only has real flags for TCP. UDP and ICMP rows are always 'SF'."""
    if (proto or '').lower() != 'tcp':
        return 'SF'
    state = str(conn_state or '').upper()
    if state in {'SF', 'S0', 'S1', 'S2', 'S3', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'SH'}:
        return state
    if state == 'RSTRH':
        return 'RSTR'
    return 'OTH'  # SHR, OTH, unknown


# ---------------------------------------------------------------------------
# Reading Zeek conn logs (TSV or JSON lines)
# ---------------------------------------------------------------------------
NUMERIC_CONN_COLUMNS = ['ts', 'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
                        'orig_ip_bytes', 'resp_ip_bytes', 'id.orig_p', 'id.resp_p']


def read_zeek_conn(path) -> pd.DataFrame:
    """Read a Zeek conn log. Supports the default TSV format and JSON lines."""
    path = Path(path)
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        first = f.read(1)
    if first == '{':
        rows = []
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        df = pd.DataFrame(rows)
    else:
        fields, rows = None, []
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.startswith('#fields'):
                    fields = line.rstrip('\n').split('\t')[1:]
                    continue
                if line.startswith('#') or not fields:
                    continue
                parts = line.rstrip('\n').split('\t')
                if len(parts) < len(fields):
                    parts += ['-'] * (len(fields) - len(parts))
                rows.append(parts[:len(fields)])
        if fields is None:
            raise ValueError("Not a Zeek conn log: no '#fields' header found")
        df = pd.DataFrame(rows, columns=fields)
        df = df.replace({'-': np.nan, '(empty)': np.nan})
    for col in NUMERIC_CONN_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    return df


# Column names used by other Zeek-based datasets (for example UWF-ZeekData22)
ZEEK_COLUMN_ALIASES = {
    'src_ip_zeek': 'id.orig_h', 'src_port_zeek': 'id.orig_p',
    'dest_ip_zeek': 'id.resp_h', 'dest_port_zeek': 'id.resp_p',
    'src_ip': 'id.orig_h', 'src_port': 'id.orig_p',
    'dst_ip': 'id.resp_h', 'dst_port': 'id.resp_p',
    'protocol': 'proto',
}


def normalise_conn_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename = {k: v for k, v in ZEEK_COLUMN_ALIASES.items() if k in df.columns and v not in df.columns}
    df = df.rename(columns=rename)
    required = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto']
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f'conn data is missing columns: {missing}')
    for col in NUMERIC_CONN_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    return df


# ---------------------------------------------------------------------------
# Feature building
# ---------------------------------------------------------------------------
def _rate(part, whole):
    return round(part / whole, 2) if whole else 0.0


def conn_to_features(conn: pd.DataFrame) -> pd.DataFrame:
    """Turn Zeek conn rows into the model's features.

    Returns a DataFrame with ALL_FEATURES columns and the same index as `conn`.
    Rows are processed in time order (the window features need that)."""
    conn = normalise_conn_columns(conn.copy())
    original_index = conn.index
    if not original_index.is_unique:
        raise ValueError('conn rows must have a unique index')
    order = conn['ts'].fillna(0).to_numpy().argsort(kind='stable')
    conn = conn.iloc[order]

    proto = conn['proto'].fillna('').astype(str).str.lower().to_numpy()
    orig_h = conn['id.orig_h'].fillna('').astype(str).to_numpy()
    resp_h = conn['id.resp_h'].fillna('').astype(str).to_numpy()
    orig_p = conn['id.orig_p'].fillna(-1).astype(int).to_numpy()
    resp_p = conn['id.resp_p'].fillna(-1).astype(int).to_numpy()
    ts = conn['ts'].fillna(0).astype(float).to_numpy()
    zeek_service = conn['service'].fillna('').astype(str).to_numpy() if 'service' in conn else [''] * len(conn)
    conn_state = conn['conn_state'].fillna('').astype(str).to_numpy() if 'conn_state' in conn else [''] * len(conn)

    n = len(conn)
    services = [kdd_service(proto[i], resp_p[i], orig_p[i], zeek_service[i]) for i in range(n)]
    # For the "same service" counters, NSL-KDD treats each unknown port as its own service
    # (a scan of 300 unknown ports has diff_srv_rate near 1), so 'private' is split by port.
    srv_keys = [f'{proto[i]}/{resp_p[i]}' if services[i] == 'private' else services[i] for i in range(n)]
    flags = [kdd_flag(proto[i], conn_state[i]) for i in range(n)]
    serr = np.array([f in SYN_ERROR_STATES for f in flags])
    rerr = np.array([f in REJ_ERROR_STATES for f in flags])

    out = {name: np.zeros(n) for name in NUMERIC_FEATURES}
    out['duration'] = conn['duration'].fillna(0).astype(float).to_numpy() if 'duration' in conn else np.zeros(n)
    out['src_bytes'] = conn['orig_bytes'].fillna(0).astype(float).to_numpy() if 'orig_bytes' in conn else np.zeros(n)
    out['dst_bytes'] = conn['resp_bytes'].fillna(0).astype(float).to_numpy() if 'resp_bytes' in conn else np.zeros(n)
    out['land'] = ((orig_h == resp_h) & (orig_p == resp_p)).astype(float)

    # --- 2 second window (sliding, counters updated as rows enter and leave)
    win = deque()
    c_host, c_srv, c_host_srv = Counter(), Counter(), Counter()
    se_host, se_srv, re_host, re_srv = Counter(), Counter(), Counter(), Counter()

    # --- last 100 connections window
    hwin = deque()
    h_host, h_srv, h_host_srv, h_host_sport = Counter(), Counter(), Counter(), Counter()
    hse_host, hse_srv, hre_host, hre_srv = Counter(), Counter(), Counter(), Counter()

    for i in range(n):
        host, srv = resp_h[i], srv_keys[i]
        # drop rows older than 2 seconds
        while win and ts[i] - ts[win[0]] > TIME_WINDOW_SECONDS:
            j = win.popleft()
            c_host[resp_h[j]] -= 1; c_srv[srv_keys[j]] -= 1; c_host_srv[(resp_h[j], srv_keys[j])] -= 1
            se_host[resp_h[j]] -= serr[j]; se_srv[srv_keys[j]] -= serr[j]
            re_host[resp_h[j]] -= rerr[j]; re_srv[srv_keys[j]] -= rerr[j]
        win.append(i)
        c_host[host] += 1; c_srv[srv] += 1; c_host_srv[(host, srv)] += 1
        se_host[host] += serr[i]; se_srv[srv] += serr[i]
        re_host[host] += rerr[i]; re_srv[srv] += rerr[i]

        count, srv_count, same = c_host[host], c_srv[srv], c_host_srv[(host, srv)]
        out['count'][i] = min(count, MAX_TIME_COUNT)
        out['srv_count'][i] = min(srv_count, MAX_TIME_COUNT)
        out['serror_rate'][i] = _rate(se_host[host], count)
        out['rerror_rate'][i] = _rate(re_host[host], count)
        out['srv_serror_rate'][i] = _rate(se_srv[srv], srv_count)
        out['srv_rerror_rate'][i] = _rate(re_srv[srv], srv_count)
        out['same_srv_rate'][i] = _rate(same, count)
        out['diff_srv_rate'][i] = _rate(count - same, count)
        out['srv_diff_host_rate'][i] = _rate(srv_count - same, srv_count)

        # last 100 connections
        if len(hwin) == HOST_WINDOW_CONNECTIONS:
            j = hwin.popleft()
            h_host[resp_h[j]] -= 1; h_srv[srv_keys[j]] -= 1; h_host_srv[(resp_h[j], srv_keys[j])] -= 1
            h_host_sport[(resp_h[j], orig_p[j])] -= 1
            hse_host[resp_h[j]] -= serr[j]; hse_srv[srv_keys[j]] -= serr[j]
            hre_host[resp_h[j]] -= rerr[j]; hre_srv[srv_keys[j]] -= rerr[j]
        hwin.append(i)
        h_host[host] += 1; h_srv[srv] += 1; h_host_srv[(host, srv)] += 1
        h_host_sport[(host, orig_p[i])] += 1
        hse_host[host] += serr[i]; hse_srv[srv] += serr[i]
        hre_host[host] += rerr[i]; hre_srv[srv] += rerr[i]

        dh, dhs, dsame = h_host[host], h_srv[srv], h_host_srv[(host, srv)]
        out['dst_host_count'][i] = min(dh, MAX_HOST_COUNT)
        out['dst_host_srv_count'][i] = min(dhs, MAX_HOST_COUNT)
        out['dst_host_same_srv_rate'][i] = _rate(dsame, dh)
        out['dst_host_diff_srv_rate'][i] = _rate(dh - dsame, dh)
        out['dst_host_same_src_port_rate'][i] = _rate(h_host_sport[(host, orig_p[i])], dh)
        out['dst_host_srv_diff_host_rate'][i] = _rate(dhs - dsame, dhs)
        out['dst_host_serror_rate'][i] = _rate(hse_host[host], dh)
        out['dst_host_srv_serror_rate'][i] = _rate(hse_srv[srv], dhs)
        out['dst_host_rerror_rate'][i] = _rate(hre_host[host], dh)
        out['dst_host_srv_rerror_rate'][i] = _rate(hre_srv[srv], dhs)

    feats = pd.DataFrame(out, index=conn.index)
    feats['protocol_type'] = proto
    feats['service'] = services
    feats['flag'] = flags
    feats = feats[ALL_FEATURES]
    return feats.loc[original_index]  # same row order as the input


# ---------------------------------------------------------------------------
# NSL-KDD
# ---------------------------------------------------------------------------
NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'attack', 'level',
]

# Standard NSL-KDD attack groups
ATTACK_GROUPS = {
    'DoS': ['apache2', 'back', 'land', 'mailbomb', 'neptune', 'pod', 'processtable',
            'smurf', 'teardrop', 'udpstorm'],
    'Probe': ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan'],
    'R2L': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'named', 'phf', 'sendmail',
            'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'worm',
            'xlock', 'xsnoop'],
    'U2R': ['buffer_overflow', 'httptunnel', 'loadmodule', 'perl', 'ps', 'rootkit',
            'sqlattack', 'xterm'],
}
ATTACK_TO_GROUP = {a: g for g, attacks in ATTACK_GROUPS.items() for a in attacks}
NSL_KDD_CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']


def nsl_kdd_label(attack: str) -> str:
    attack = str(attack).strip().lower()
    if attack == 'normal':
        return 'Normal'
    if attack not in ATTACK_TO_GROUP:
        raise ValueError(f'Unknown NSL-KDD attack name: {attack!r}')
    return ATTACK_TO_GROUP[attack]
