"""Verify CLI, exports, all demos and localhost Flask in an unpacked submission."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(output: Path) -> dict:
    if output.exists() and any(output.iterdir()):
        raise ValueError('Use a new evidence directory')
    output.mkdir(parents=True, exist_ok=True)
    from app import create_app
    from src.demo_service import run_all_demos
    from experiments.audit_research_metrics import audit
    from experiments.audit_expanded_study import audit as expanded_audit
    import requests
    from werkzeug.serving import make_server
    batch = run_all_demos(ROOT / 'config/algorithm_policy.json')
    (output / 'demos.json').write_text(json.dumps(batch, ensure_ascii=False, indent=2), encoding='utf-8')
    result = {'demo_total': batch['total'], 'demo_success': batch['success'],
              'historical90': audit(ROOT / 'reports/research_results'),
              'historical114': expanded_audit(ROOT / 'reports/research_expanded/post_tls_20261010'),
              'cli': [], 'http': []}
    for label, args in [('dataset', []), ('default', ['google.com']), ('advanced', ['google.com', '--advanced'])]:
        command = [sys.executable, '-X', 'utf8', str(ROOT / 'main.py'), *args]
        if args:
            command += ['--json', str(output / f'{label}.json'), '--html', str(output / f'{label}.html')]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=150)
        (output / f'{label}.log').write_bytes(process.stdout + process.stderr)
        record = {'mode': label, 'exit_code': process.returncode}
        if args:
            view = json.loads((output / f'{label}.json').read_text(encoding='utf-8'))
            record.update(security=view['security'], errors=view.get('scan_error'),
                          certificate_present=bool(view.get('certificate')),
                          html_export=(output / f'{label}.html').stat().st_size > 100)
        result['cli'].append(record)
    server = make_server('127.0.0.1', 0, create_app())
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path, method, data, expected in [('/', 'GET', None, 200), ('/demo', 'GET', None, 200),
                ('/demo', 'POST', {'action': 'all'}, 200),
                ('/scan', 'POST', {'hostname': 'https://invalid.test/path'}, 400)]:
            response = requests.request(method, f'http://127.0.0.1:{server.server_port}{path}', data=data, timeout=90)
            result['http'].append({'path': path, 'method': method, 'status': response.status_code, 'expected': expected})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    result['passed'] = (batch['total'] == batch['success'] == 14 and result['historical90']['verified']
        and result['historical114']['verified'] and all(r['status'] == r['expected'] for r in result['http'])
        and all(r['exit_code'] == 0 and (r['mode'] == 'dataset' or r['certificate_present'] and r['html_export']) for r in result['cli']))
    (output / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    result = run(parser.parse_args().output_dir.resolve())
    print('Smoke passed:', result['passed'], 'Demo:', result['demo_success'], '/', result['demo_total'])
    raise SystemExit(0 if result['passed'] else 1)
