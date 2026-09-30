# -*- coding: utf-8 -*-
"""Node 解析的参数化回归测试：每种协议都验证 parse -> url -> parse 的往返一致性。"""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fetch import Node, dedup_key, UnsupportedType  # noqa: E402


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


CASES = [
    # (原始链接, 期望类型, 关键字段)
    ("tuic://uuid-1234:pass123@example.com:443?sni=example.com&congestion_controller=bbr&alpn=h3#TestTUIC",
     'tuic', {'server': 'example.com', 'port': 443, 'name': 'TestTUIC'}),
    ("anytls://pass8888@example.com:8443?sni=example.com&allowInsecure=1#TestAnyTLS",
     'anytls', {'server': 'example.com', 'port': 8443, 'name': 'TestAnyTLS'}),
    ("ss://YWVzLTI1Ni1nY206dGVzdA==@[2001:db8::1]:8388#IPv6SS",
     'ss', {'server': '2001:db8::1', 'port': 8388, 'cipher': 'aes-256-gcm'}),
    ("ss://" + b64(b"ss://aes-256-gcm:pwd@[2001:db8::5]:443#Full"),
     'ss', {'server': '2001:db8::5', 'port': 443, 'password': 'pwd'}),
    ("ss://YWVzLTI1Ni1nY206dGVzdA==@example.com:8388#Plain",
     'ss', {'server': 'example.com', 'port': 8388}),
    ("ssr://example.com:443:origin:aes-256-cfb:tls1.2_ticket_auth:"
     + base64.b64encode(b"password").decode() + "/?remarks=" + base64.b64encode(b"cName").decode(),
     'ssr', {'server': 'example.com', 'port': 443, 'password': 'password', 'name': 'cName'}),
    ("hysteria2://pw@example.com:443?sni=a.com#Hy2",
     'hysteria2', {'server': 'example.com', 'port': 443, 'password': 'pw'}),
    ("vmess://" + base64.b64encode(b'{"v":"2","ps":"VM","add":"1.2.3.4","port":"443","id":"88888888-8888-8888-8888-888888888888","aid":"0","scy":"auto","net":"tcp","type":"none","tls":"tls"}').decode(),
     'vmess', {'server': '1.2.3.4', 'port': 443}),
    ("trojan://pw@example.com:443?sni=a.com&type=ws&path=%2Fws#Tro",
     'trojan', {'server': 'example.com', 'port': 443, 'password': 'pw'}),
    ("vless://uuid-1@example.com:443?type=ws&path=%2Fws&security=tls&sni=a.com#Vless",
     'vless', {'server': 'example.com', 'port': 443}),
]

IDS = [c[1] + '-' + str(i) for i, c in enumerate(CASES)]


@pytest.mark.parametrize("raw,etype,fields", CASES, ids=IDS)
def test_roundtrip(raw, etype, fields):
    """parse -> url -> parse 往返后关键字段一致。"""
    n = Node(raw)
    assert n.type == etype
    for k, v in fields.items():
        assert n.data.get(k) == v, f"field {k}: {n.data.get(k)!r} != {v!r}"
    n2 = Node(n.url)
    assert n2.type == n.type
    for k, v in fields.items():
        assert n2.data.get(k) == v, f"roundtrip field {k}: {n2.data.get(k)!r} != {v!r}"


def test_roundtrip_exact_key():
    """往返后 dedup_key 完全一致（去重正确性的前提）。"""
    for raw, _, _ in CASES:
        n = Node(raw)
        n2 = Node(n.url)
        assert dedup_key(n) == dedup_key(n2), raw[:60]


def test_hash_collision_no_overwrite():
    """dedup_key 不同的两个节点即使 hash 碰撞也不该被 merge 判定为重复。"""
    from fetch import Node as N
    a = N("ss://YWVzLTI1Ni1nY206dGVzdA==@a.example.com:8388#A")
    b = N("ss://YWVzLTI1Ni1nY206dGVzdA==@b.example.com:8388#B")
    assert dedup_key(a) != dedup_key(b)


def test_fake_node_detected():
    n = Node("ss://YWVzLTI1Ni1nY206dGVzdA==@8.8.8.8:8388#Fake")
    assert n.isfake is True


def test_unsupported_type():
    with pytest.raises(UnsupportedType):
        Node("wireguard://whatever")
