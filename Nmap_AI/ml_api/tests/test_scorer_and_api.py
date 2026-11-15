import shutil

import pytest

from conftest import FIXTURES, ML_API, REPO_ROOT
from scorer import DEFAULT_MODEL_PATH, load_model, score_conn_log

SAMPLE = FIXTURES / 'sample_conn.log'


@pytest.fixture(scope='module')
def model():
    return load_model(DEFAULT_MODEL_PATH)


def test_shipped_model_scores_sample(model, tmp_path):
    out = tmp_path / 'pred.csv'
    s = score_conn_log(SAMPLE, model, out)
    assert s['total_records'] == 1000
    assert out.exists()
    # 300 normal rows, a 300-port scan and a 400-connection SYN flood
    assert s['normal'] >= 290
    assert s['attack_breakdown'].get('DoS', 0) >= 380
    assert s['attack_breakdown'].get('Probe', 0) >= 250
    labels = {(i['label'], i['dst_ip']) for i in s['incidents']}
    assert ('DoS', '192.0.2.30') in labels
    assert ('Probe', '192.0.2.20') in labels
    top = s['incidents'][0]
    assert top['reasons'], 'every incident should say why'
    assert {'feature', 'description', 'value'} <= set(top['reasons'][0])


def test_class_names_are_words_not_numbers(model):
    assert model.classes == sorted(['DoS', 'Normal', 'Probe', 'R2L', 'U2R'])


def test_empty_log(model, tmp_path):
    p = tmp_path / 'empty.log'
    p.write_text('#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n')
    s = score_conn_log(p, model)
    assert s['total_records'] == 0 and 'warning' in s


@pytest.fixture
def client(tmp_path, monkeypatch):
    import app as app_module
    results = tmp_path / 'results'
    pcaps = tmp_path / 'pcaps'
    (results / 'zeek_1').mkdir(parents=True)
    pcaps.mkdir()
    shutil.copy(SAMPLE, results / 'zeek_1' / 'conn_1.log')
    monkeypatch.setattr(app_module, 'RESULTS_DIR', results)
    monkeypatch.setattr(app_module, 'PCAP_DIR', pcaps)
    return app_module.app.test_client()


def test_api_predict(client):
    r = client.post('/api/analysis/predict', json={'conn_log': 'conn_1.log'})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['total_records'] == 1000
    assert body['output_csv'].startswith('predictions_')
    # the CSV can be downloaded by name
    assert client.get(f"/api/analysis/download/{body['output_csv']}").status_code == 200


def test_api_predict_rejects_paths_outside_results(client):
    r = client.post('/api/analysis/predict', json={'conn_log': '/etc/passwd'})
    assert r.status_code == 400


def test_api_download_rejects_bad_names(client):
    assert client.get('/api/analysis/download/.env').status_code == 400
    assert client.get('/api/analysis/download/..%5Capp.py').status_code == 400


def test_api_capture_validation(client):
    assert client.post('/api/analysis/start-tcpdump', json={'duration': 1}).status_code == 400
    assert client.post('/api/analysis/start-tcpdump', json={'interface': 'eth0; reboot'}).status_code == 400


def test_health_reports_model(client):
    body = client.get('/health').get_json()
    assert body['model_loaded'] is True
    assert body['model']['classes']


def test_train_quick_runs(tmp_path):
    kdd = REPO_ROOT / 'KDD+.txt'
    if not kdd.exists():
        pytest.skip('KDD+.txt not present')
    import train
    meta = train.main(['--dataset', 'nslkdd', '--data', str(kdd), '--quick', '--out-dir', str(tmp_path)])
    assert (tmp_path / 'netanomaly_model.joblib').exists()
    assert (tmp_path / 'MODEL_CARD.md').exists()
    # honest test numbers are far below the misleading random-split number
    r = meta['results']
    assert r['random_forest_random_split']['accuracy'] > 0.95
    assert 0.6 < r['lightgbm']['accuracy'] < 0.95


def test_uwf_loader_on_uwf_style_columns(tmp_path):
    """UWF-ZeekData22 uses its own column names. Check the loader maps them.

    This uses made-up rows in the UWF layout, not the real dataset."""
    import pandas as pd
    import train
    from features import read_zeek_conn
    df = read_zeek_conn(SAMPLE).rename(columns={
        'id.orig_h': 'src_ip_zeek', 'id.orig_p': 'src_port_zeek',
        'id.resp_h': 'dest_ip_zeek', 'id.resp_p': 'dest_port_zeek'})
    df['label_tactic'] = ['none'] * 300 + ['Reconnaissance'] * 300 + ['Impact'] * 400
    d = tmp_path / 'uwf'
    d.mkdir()
    df.to_csv(d / 'part1.csv', index=False)
    X_train, y_train, X_test, y_test, note = train.load_uwf(d, min_class_rows=50)
    assert set(y_train) == {'Normal', 'Reconnaissance', 'Impact'}
    assert len(X_train) + len(X_test) == 1000
    assert 'UWF' in note
