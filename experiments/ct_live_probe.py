"""Record real engine CT evidence; never replace historical research outputs."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))
import argparse
from datetime import datetime, timezone
import hashlib
import json
from cryptography.hazmat.primitives import serialization
import src.certificate_security as engine
from src.certificate_fetcher import fetch_peer_chain
from src.certificate_service import build_view_model
from src.ct_registry import load_official_registry, KEY_PATH
from src.ct_inclusion import check_inclusion
from src.revocation_network import fetch_bytes


def run(output: Path) -> None:
    """Capture signed Google list and STH/proof bytes for fixed public websites."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Không ghi đè thư mục evidence đã có.")
    output.mkdir(parents=True,exist_ok=True)
    (output/"publisher.pem").write_bytes(KEY_PATH.read_bytes())
    original_registry, original_proof = engine.load_official_registry, engine.check_inclusion
    try:
        for hostname in ("google.com","github.com","cloudflare.com"):
            folder = output/hostname
            folder.mkdir()
            downloads=[]
            def capture(url, **kwargs):
                data = fetch_bytes(url,**kwargs)
                name = f"response_{len(downloads)+1}.bin"
                (folder/name).write_bytes(data)
                downloads.append({"url":url,"file":name,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)})
                return data
            def tls(*args):
                fetched = fetch_peer_chain(*args)
                for index,der in enumerate(fetched.chain_der):
                    (folder/f"chain_{index}.der").write_bytes(der)
                return fetched
            engine.load_official_registry = lambda: load_official_registry(fetcher=capture)
            engine.check_inclusion = lambda *args,**kwargs: check_inclusion(*args,fetcher=capture,**kwargs)
            started = datetime.now(timezone.utc)
            import time
            tick = time.perf_counter()
            result = engine.analyze_certificate(hostname,443,10,ROOT/"data/log_list.json",ROOT/"config/algorithm_policy.json",fetcher=tls,advanced=True)
            view = build_view_model(hostname,result,time.perf_counter()-tick)
            view["checked_at"] = started.isoformat()
            (folder/"result.json").write_text(json.dumps(view,ensure_ascii=False,indent=2),encoding="utf8")
            (folder/"downloads.json").write_text(json.dumps(downloads,ensure_ascii=False,indent=2),encoding="utf8")
            print(hostname,view["security"]["status"],[(s["status"]) for s in view["extensions"]["sct_verification"]],view["extensions"]["inclusion"]["status"])
    finally:
        engine.load_official_registry, engine.check_inclusion = original_registry, original_proof


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir",type=Path,required=True)
    run(parser.parse_args().output_dir.resolve())
