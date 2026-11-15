import json

import pandas as pd
import pytest

from conftest import FIXTURES
from features import (ALL_FEATURES, conn_to_features, kdd_flag, kdd_service, nsl_kdd_label,
                      read_zeek_conn)
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from make_sample_conn import write as write_sample  # noqa: E402


@pytest.mark.parametrize('proto,resp_port,orig_port,zeek,expected', [
    ('tcp', 80, 5000, 'http', 'http'),
    ('tcp', 443, 5000, 'ssl', 'http_443'),
    ('tcp', 6001, 5000, '-', 'X11'),
    ('udp', 53, 5000, 'dns', 'domain_u'),
    ('tcp', 53, 5000, 'dns', 'domain'),
    ('tcp', 31337, 5000, '', 'private'),
    ('tcp', 31337, 5000, 'http', 'http'),      # unknown port, Zeek saw HTTP
    ('icmp', 0, 8, '', 'eco_i'),              # echo request (type 8 is in orig_p)
    ('icmp', 0, 0, '', 'ecr_i'),
])
def test_kdd_service(proto, resp_port, orig_port, zeek, expected):
    assert kdd_service(proto, resp_port, orig_port, zeek) == expected


def test_kdd_flag():
    assert kdd_flag('tcp', 'S0') == 'S0'
    assert kdd_flag('tcp', 'RSTRH') == 'RSTR'
    assert kdd_flag('tcp', 'SHR') == 'OTH'
    assert kdd_flag('udp', 'S0') == 'SF'  # NSL-KDD only has flags for TCP


def test_nsl_kdd_labels():
    assert nsl_kdd_label('normal') == 'Normal'
    assert nsl_kdd_label('neptune') == 'DoS'
    assert nsl_kdd_label('loadmodule') == 'U2R'
    assert nsl_kdd_label('httptunnel') == 'U2R'
    assert nsl_kdd_label('xlock') == 'R2L'
    with pytest.raises(ValueError):
        nsl_kdd_label('loadmdoule')  # the old typo must not silently become "normal"


def _conn(rows):
    cols = ['ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service',
            'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    return pd.DataFrame(rows, columns=cols)


def test_window_features_by_hand():
    # 3 connections to host A in 1 second (2 to port 80, 1 rejected to 22), then one 5s later
    conn = _conn([
        (0.0, 'x', 1000, 'A', 80, 'tcp', 'http', 1.0, 100, 200, 'SF'),
        (0.5, 'x', 1001, 'A', 80, 'tcp', 'http', 1.0, 100, 200, 'S0'),
        (1.0, 'x', 1002, 'A', 22, 'tcp', '', 0.0, 0, 0, 'REJ'),
        (6.0, 'y', 1003, 'B', 80, 'tcp', 'http', 1.0, 100, 200, 'SF'),
    ])
    f = conn_to_features(conn)
    assert list(f.columns) == ALL_FEATURES
    third = f.iloc[2]
    assert third['count'] == 3
    assert third['srv_count'] == 1            # only this one to ssh
    assert third['serror_rate'] == 0.33       # 1 of 3 half-open
    assert third['rerror_rate'] == 0.33       # 1 of 3 rejected
    assert third['same_srv_rate'] == 0.33
    assert third['diff_srv_rate'] == 0.67
    fourth = f.iloc[3]
    assert fourth['count'] == 1               # the A connections are older than 2 seconds
    assert fourth['srv_count'] == 1
    assert fourth['dst_host_count'] == 1      # last-100 window: only one to B
    assert fourth['dst_host_srv_count'] == 3  # http seen 3 times in the last 100 (any host)
    assert fourth['dst_host_srv_diff_host_rate'] == 0.67


def test_output_keeps_input_order():
    conn = _conn([
        (1.5, 'x', 1, 'A', 80, 'tcp', 'http', 1, 1, 1, 'SF'),
        (1.0, 'x', 2, 'A', 80, 'tcp', 'http', 1, 1, 1, 'SF'),
    ])
    f = conn_to_features(conn)
    assert list(f.index) == [0, 1]
    assert f.loc[0, 'count'] == 2 and f.loc[1, 'count'] == 1


def test_scan_and_flood_look_different_from_normal(tmp_path):
    path = tmp_path / 'conn.log'
    labels = write_sample(path)
    f = conn_to_features(read_zeek_conn(path))
    f['label'] = labels
    by = f.groupby('label').mean(numeric_only=True)
    assert by.loc['flood', 'serror_rate'] > 0.9
    assert by.loc['scan', 'diff_srv_rate'] > 0.9   # every port is a different service
    assert by.loc['scan', 'dst_host_same_src_port_rate'] > 0.5
    assert by.loc['normal', 'serror_rate'] < 0.05


def test_json_and_tsv_logs_give_same_features(tmp_path):
    tsv = tmp_path / 'conn.log'
    write_sample(tsv)
    df = read_zeek_conn(tsv)
    js = tmp_path / 'conn.json'
    with open(js, 'w') as fh:
        for rec in df.to_dict(orient='records'):
            fh.write(json.dumps({k: v for k, v in rec.items() if pd.notna(v)}) + '\n')
    a = conn_to_features(df)
    b = conn_to_features(read_zeek_conn(js))
    pd.testing.assert_frame_equal(a.reset_index(drop=True), b.reset_index(drop=True), check_dtype=False)


def test_fixture_is_valid():
    df = read_zeek_conn(FIXTURES / 'sample_conn.log')
    assert len(df) == 1000
