"""Capture actual Flask UI, exports and responsive geometry with local Edge CDP."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app import create_app
from experiments.browser_smoke import CDP
import requests
from jinja2 import FileSystemLoader
from werkzeug.serving import make_server


def run(output, assets_root, enhanced):
    if output.exists():
        raise ValueError('Evidence directory must be new')
    output.mkdir(parents=True)
    application = create_app()
    application.jinja_loader = FileSystemLoader(str(assets_root / 'templates'))
    application.static_folder = str(assets_root / 'static')
    server = make_server('127.0.0.1', 0, application, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    profile = ROOT / '.cache' / ('ui_browser_' + uuid.uuid4().hex)
    browser = subprocess.Popen([r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--disable-extensions', '--disable-background-networking', '--remote-debugging-port=0',
        f'--user-data-dir={profile}', 'about:blank'], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    client = None
    result = {'assets_root': str(assets_root), 'checks': {}, 'screenshots': [],
              'limitations': ['Viewport emulation, not physical devices; no OS clipboard check.']}
    try:
        deadline = time.monotonic() + 30
        active = profile / 'DevToolsActivePort'
        while not active.exists() and time.monotonic() < deadline:
            time.sleep(.1)
        port = int(active.read_text().splitlines()[0])
        targets = requests.get(f'http://127.0.0.1:{port}/json/list', timeout=5).json()
        client = CDP(next(t['webSocketDebuggerUrl'] for t in targets if t['type'] == 'page'))
        client.socket.settimeout(120)
        client.call('Page.enable')
        client.call('Browser.setDownloadBehavior', {'behavior': 'allow', 'downloadPath': str(output.resolve())})

        def nav(path, ready):
            client.evaluate('document.body.replaceChildren()')
            client.call('Page.navigate', {'url': origin + path})
            client.wait(ready, timeout=120)

        def capture(page, expanded=False):
            for width, height in [(390,844),(768,1024),(1366,900),(1920,1080)]:
                client.call('Emulation.setDeviceMetricsOverride', {'width':width,'height':height,'deviceScaleFactor':1,'mobile':False})
                client.evaluate('window.scrollTo(0,0)')
                time.sleep(.15)
                key = f'{page}_{width}'
                geometry = client.evaluate("""({viewport:innerWidth, document:document.documentElement.scrollWidth,
                    overflow:[...document.querySelectorAll('main *')].filter(e=>{const r=e.getBoundingClientRect();return r.width>0 && r.right>innerWidth+1 && !e.closest('.table-scroll')}).slice(0,8).map(e=>e.tagName+'.'+e.className)})""")
                result['checks'][key + '_no_overflow'] = geometry['document'] <= width
                if geometry['document'] > width:
                    result.setdefault('overflow_details', {})[key] = geometry
                screenshot = client.call('Page.captureScreenshot', {'format':'png','captureBeyondViewport':False})
                (output / f'{key}.png').write_bytes(base64.b64decode(screenshot['data']))
                result['screenshots'].append(f'{key}.png')
            if expanded:
                client.evaluate("document.querySelectorAll('details').forEach(e=>e.open=true)")
                client.call('Emulation.setDeviceMetricsOverride', {'width':390,'height':844,'deviceScaleFactor':1,'mobile':False})
                result['checks'][page+'_expanded_no_overflow'] = client.evaluate('document.documentElement.scrollWidth <= innerWidth')
                client.evaluate("document.querySelectorAll('details').forEach(e=>e.open=false)")

        def downloaded(name):
            target = output / name
            end = time.monotonic()+15
            while (not target.exists() or target.with_suffix(target.suffix+'.crdownload').exists()) and time.monotonic()<end:
                time.sleep(.1)
            return target

        nav('/', "!!document.getElementById('scan-form')")
        capture('home')
        if enhanced:
            client.call('Emulation.setDeviceMetricsOverride', {'width':390,'height':844,'deviceScaleFactor':1,'mobile':False})
            result['checks']['advanced_collapsed_by_default'] = client.evaluate("!document.querySelector('.advanced-options').open && !document.querySelector('[name=advanced]').checked")
            client.evaluate("document.querySelector('.nav-toggle').click()")
            result['checks']['mobile_menu_opens'] = client.evaluate("document.querySelector('.nav-toggle').getAttribute('aria-expanded')==='true' && document.getElementById('main-nav').getBoundingClientRect().height>0")
            client.evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))")
            result['checks']['mobile_menu_escape'] = client.evaluate("document.querySelector('.nav-toggle').getAttribute('aria-expanded')==='false'")
            client.evaluate("document.getElementById('hostname').value='https://bad.test/path';document.getElementById('scan-form').requestSubmit()")
            result['checks']['client_error'] = client.evaluate("!document.getElementById('client-error').hidden && !document.getElementById('scan-button').disabled")
        client.evaluate("document.getElementById('hostname').value='google.com';document.getElementById('scan-form').requestSubmit()")
        result['checks']['loading'] = client.evaluate("document.getElementById('scan-button').disabled && !document.getElementById('scan-spinner').hidden")
        client.wait("!!document.getElementById('final-result')", timeout=120)
        result['default_verdict'] = client.evaluate("document.querySelector('#final-result [data-status]').dataset.status")
        capture('result_default', enhanced)
        nav('/', "!!document.getElementById('scan-form')")
        if enhanced:
            client.evaluate("document.querySelector('.advanced-options').open=true")
        client.evaluate("document.querySelector('[name=advanced]').checked=true;document.getElementById('hostname').value='google.com';document.getElementById('scan-form').requestSubmit()")
        client.wait("!!document.getElementById('final-result')", timeout=120)
        result['advanced_verdict'] = client.evaluate("document.querySelector('#final-result [data-status]').dataset.status")
        if enhanced:
            result['checks']['eight_detail_groups'] = client.evaluate("document.querySelectorAll('.result-grid>.detail-panel').length===8 && !document.querySelector('.result-grid>.detail-panel[open]')")
            result['checks']['score_and_verdict_separate'] = client.evaluate("document.getElementById('security-score').closest('.score-card')!==document.getElementById('final-result').parentElement")
            client.evaluate("document.querySelector('[data-export=json]').click()")
            payload = json.loads(downloaded('DT007-google.com.json').read_text(encoding='utf-8'))
            result['checks']['json_matches_snapshot'] = payload == client.evaluate("JSON.parse(document.getElementById('result-data').textContent)")
            client.evaluate("document.querySelector('[data-export=html]').click()")
            exported = downloaded('DT007-google.com.html').read_text(encoding='utf-8')
            result['checks']['html_standalone'] = '<style>' in exported and '<script' not in exported and 'rel="stylesheet"' not in exported and 'google.com' in exported
            result['checks']['all_raw_evidence_present'] = client.evaluate("JSON.parse(document.getElementById('raw-result').textContent).security.status===JSON.parse(document.getElementById('result-data').textContent).security.status")
        capture('result_advanced', enhanced)
        if enhanced:
            # Inspect the exported file using the browser; no server resource is required.
            client.call('Page.navigate', {'url': (output/'DT007-google.com.html').resolve().as_uri()})
            client.wait("!!document.getElementById('final-result')")
            result['checks']['exported_html_opens'] = client.evaluate("document.styleSheets.length>0 && document.querySelectorAll('.result-grid>.detail-panel[open]').length===8 && document.documentElement.scrollWidth<=innerWidth")
        nav('/demo', "!!document.getElementById('case-id')")
        capture('demo')
        if enhanced:
            result['checks']['fourteen_case_cards'] = client.evaluate("document.querySelectorAll('.case-card').length===14")
            client.evaluate("document.querySelector('.case-form').requestSubmit()")
        else:
            client.evaluate("document.getElementById('demo-form').requestSubmit()")
        client.wait("!!document.getElementById('demo-comparison')", timeout=120)
        if enhanced:
            result['checks']['single_test_vs_security'] = client.evaluate("document.querySelector('.demo-verdicts').innerText.includes('KHÔNG ĐẠT') && document.querySelector('.demo-verdicts').innerText.includes('KIỂM THỬ THÀNH CÔNG')")
        capture('demo_single', enhanced)
        nav('/demo', "!!document.querySelector('.batch-form')")
        client.evaluate("document.querySelector('.batch-form').requestSubmit()")
        client.wait("!!document.getElementById('batch-results')", timeout=120)
        result['checks']['fourteen_demos_passed'] = client.evaluate("document.querySelectorAll('tbody tr').length===14 && [...document.querySelectorAll('tbody tr')].every(r=>r.innerText.includes('KIỂM THỬ THÀNH CÔNG'))")
        client.evaluate("document.getElementById('export-batch').click()")
        import csv
        with downloaded('DT007-kiem-thu-tong-hop.csv').open(encoding='utf-8-sig', newline='') as stream:
            result['checks']['csv_export'] = len(list(csv.DictReader(stream))) == 14
        capture('demo_batch', enhanced)
        result['passed'] = all(result['checks'].values())
    except Exception as exc:
        result.update(error=f'{type(exc).__name__}: {exc}', passed=False)
    finally:
        if client:
            try:
                client.call('Browser.close')
            except Exception:
                pass
            client.socket.close()
        try:
            browser.wait(timeout=10)
        except subprocess.TimeoutExpired:
            browser.terminate()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (output/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--assets-root',type=Path,default=ROOT)
    parser.add_argument('--enhanced',action='store_true')
    args=parser.parse_args()
    result=run(args.output_dir.resolve(),args.assets_root.resolve(),args.enhanced)
    print(json.dumps(result,ensure_ascii=False))
    raise SystemExit(0 if result['passed'] else 1)
