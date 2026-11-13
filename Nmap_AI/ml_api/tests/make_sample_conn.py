"""Write a small, made-up Zeek conn.log with normal traffic, a port scan and a SYN flood.

  python tests/make_sample_conn.py tests/fixtures/sample_conn.log

All addresses are from documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""
import random
import sys

FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service',
          'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp',
          'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
          'tunnel_parents']
TYPES = ['time', 'string', 'addr', 'port', 'addr', 'port', 'enum', 'string', 'interval', 'count',
         'count', 'string', 'bool', 'bool', 'count', 'string', 'count', 'count', 'count', 'count',
         'set[string]']


def rows(seed=7):
    rnd = random.Random(seed)
    t = 1_700_000_000.0
    out = []
    uid = 0

    def add(ts, src, sport, dst, dport, proto, service, dur, ob, rb, state, label):
        nonlocal uid
        uid += 1
        out.append(([f'{ts:.6f}', f'C{uid:06d}', src, str(sport), dst, str(dport), proto, service,
                     '-' if dur is None else f'{dur:.6f}', '-' if ob is None else str(ob),
                     '-' if rb is None else str(rb), state, 'T', 'F', '0', '-', '1', '60', '1', '60',
                     '(empty)'], label))

    # 60 s of normal browsing and DNS from one client, spread out
    for i in range(300):
        ts = t + i * 0.2
        if i % 3 == 0:
            add(ts, '192.0.2.10', rnd.randint(40000, 60000), '192.0.2.1', 53, 'udp', 'dns',
                0.02, 40, 120, 'SF', 'normal')
        else:
            dst = f'198.51.100.{rnd.randint(1, 30)}'
            add(ts, '192.0.2.10', rnd.randint(40000, 60000), dst, 443, 'tcp', 'ssl',
                rnd.uniform(0.5, 30), rnd.randint(500, 3000), rnd.randint(2000, 90000), 'SF', 'normal')
    # SYN port scan: one source, one target, 300 ports in about 1.5 seconds
    t2 = t + 61
    for i, port in enumerate(rnd.sample(range(1, 1024), 300)):
        state = 'REJ' if i % 4 == 0 else 'S0'
        add(t2 + i * 0.005, '203.0.113.66', 55555, '192.0.2.20', port, 'tcp', '-',
            None, None, None, state, 'scan')
    # SYN flood: many sources, same target port, half-open
    t3 = t + 70
    for i in range(400):
        add(t3 + i * 0.002, f'203.0.113.{rnd.randint(1, 254)}', rnd.randint(1024, 65535),
            '192.0.2.30', 80, 'tcp', '-', None, None, None, 'S0', 'flood')
    return out


def write(path):
    data = rows()
    with open(path, 'w') as f:
        f.write('#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n')
        f.write('#fields\t' + '\t'.join(FIELDS) + '\n#types\t' + '\t'.join(TYPES) + '\n')
        for r, _ in data:
            f.write('\t'.join(r) + '\n')
        f.write('#close\t2023-11-14-22-15-00\n')
    return [label for _, label in data]


if __name__ == '__main__':
    write(sys.argv[1] if len(sys.argv) > 1 else 'sample_conn.log')
