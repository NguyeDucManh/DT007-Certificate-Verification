"""Root khác điểm neo; không đủ đường dẫn không được tin cậy."""
from dataclasses import replace
from src.chain_validator import validate_chain
from src.certificate_service import build_view_model
from src.certificate_security import CertificateAnalysis
from src.security_evaluator import SecurityResult


def view(chain):
    return build_view_model('example.test', CertificateAnalysis(None,None,None,chain,None,None,SecurityResult(chain.status,{},()),{}),0)


def test_intermediate_not_trusted_without_anchor(chain_factory, reference_time):
    leaf, intermediate, root = chain_factory()
    result = validate_chain([leaf,intermediate],[],reference_time)
    assert result.trust == 'FAIL' and result.trust_anchor is None
    assert view(result)['chain']['certificates'][-1]['role'] == 'Intermediate #1'


def test_root_from_store_not_peer(chain_factory, reference_time):
    leaf, intermediate, root = chain_factory()
    result = validate_chain([leaf,intermediate],[root],reference_time,peer_chain=[leaf,intermediate])
    assert result.trust == 'PASS' and result.trust_anchor == root
    data = view(result)['chain']['certificates']
    assert data[-1]['role'] == 'Root CA / Trust Anchor'
    assert 'không nằm trong chuỗi máy chủ gửi' in data[-1]['origin']
    assert data[1]['origin'] == 'Máy chủ gửi qua TLS'


def test_direct_intermediate_anchor_not_root(chain_factory, reference_time):
    leaf, intermediate, root = chain_factory()
    result = validate_chain([leaf,intermediate],[intermediate],reference_time,peer_chain=[leaf,intermediate])
    assert result.trust_anchor == intermediate and result.trust == 'PASS'
    assert view(result)['chain']['certificates'][-1]['role'] == 'Intermediate Trust Anchor'


def test_missing_intermediate_cannot_complete(chain_factory, reference_time):
    leaf, intermediate, root = chain_factory()
    assert validate_chain([leaf],[root],reference_time).trust == 'FAIL'
