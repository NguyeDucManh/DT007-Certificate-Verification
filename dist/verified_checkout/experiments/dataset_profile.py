"""Record provenance, checksum, schema and quality of the pinned CT Log List snapshot."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'https://www.gstatic.com/ct/log_list/v3/log_list.json'

def profile(path: Path) -> dict:
    raw = path.read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get('operators'), list):
        raise ValueError('Invalid CT log list schema')
    states, kinds, errors = Counter(), Counter(), []
    log_ids, urls = set(), set()
    for i, operator in enumerate(data['operators']):
        if not isinstance(operator, dict):
            errors.append(f'operators[{i}] is not object'); continue
        for kind in ('logs','tiled_logs'):
            logs = operator.get(kind, [])
            if not isinstance(logs, list):
                errors.append(f'operators[{i}].{kind} not list'); continue
            for j, log in enumerate(logs):
                kinds[kind] += 1
                if not isinstance(log, dict):
                    errors.append(f'operators[{i}].{kind}[{j}] not object'); continue
                state = log.get('state')
                states[next(iter(state)) if isinstance(state, dict) and state else 'unknown'] += 1
                ident = log.get('log_id')
                if not isinstance(ident,str) or not ident: errors.append(f'missing/invalid log_id at {i}/{kind}/{j}')
                elif ident in log_ids: errors.append(f'duplicate log_id at {i}/{kind}/{j}')
                else: log_ids.add(ident)
                url = log.get('url') or log.get('submission_url')
                if url is not None and not isinstance(url,str):
                    errors.append(f'invalid URL at {i}/{kind}/{j}'); continue
                if url in urls: errors.append(f'duplicate url at {i}/{kind}/{j}')
                elif url: urls.add(url)
    return {'source_url':SOURCE,'local_file':str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
            'schema_url':'https://www.gstatic.com/ct/log_list/v3/log_list_schema.json',
            'license_status':'Not verified: source URL does not by itself establish redistribution permission',
            'acquisition_time':'Not recorded for this existing local snapshot; profile_created_utc is not download time',
            'profile_created_utc':datetime.now(timezone.utc).isoformat(),
            'dataset_timestamp':data.get('log_list_timestamp'), 'version':data.get('version'),
            'size_bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest(),
            'operators':len(data['operators']), 'logs_by_type':dict(kinds),
            'states':dict(states),'unique_log_ids':len(log_ids), 'quality_warnings':errors,
            'notes':'CT Log List metadata, NOT a dataset of labeled TLS certificates; pin snapshot for reproducibility.'}

if __name__=='__main__':
    result=profile(ROOT/'data'/'log_list.json')
    out=ROOT/'reports'/'ct_dataset_profile.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print('Saved:',out,'operators:',result['operators'],'log counts:',result['logs_by_type'])
