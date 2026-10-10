#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 CI 中对 nodes.check.yml 的节点做真实代理测活（mihomo 内核）。

与 fetch.py 的 TCP 粗筛不同，这里是协议级测试：
  启动 mihomo → 逐个调用 /proxies/{name}/delay → 延迟测试成功的才是真可用。

用法：
  python alive_check.py [--url URL] [--timeout MS] [--workers N] [--in FILE] [--out FILE]
"""
import argparse
import concurrent.futures as cf
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import yaml

MIHOMO_VER = "v1.19.15"
MIHOMO_URL = ("https://github.com/MetaCubeX/mihomo/releases/download/"
              "{v}/mihomo-linux-amd64-{v}.gz")
API = "http://127.0.0.1:19090"
TEST_URL = "https://www.gstatic.com/generate_204"


def download_mihomo(dst: str = "./mihomo") -> str:
    if os.path.exists(dst):
        return dst
    url = MIHOMO_URL.format(v=MIHOMO_VER)
    print(f"下载 mihomo {MIHOMO_VER} ...", flush=True)
    gz = dst + ".gz"
    urllib.request.urlretrieve(url, gz)
    import gzip
    with gzip.open(gz, "rb") as f_in, open(dst, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.chmod(dst, 0o755)
    os.remove(gz)
    return dst



def sanitize_node(n: dict) -> dict:
    """修正上游源里的过时/不兼容字段，避免 mihomo 因单个节点拒绝启动。

    - fingerprint: 新版 mihomo 中该字段专用于 TLS 证书固定（证书 SHA256），
      浏览器指纹应写作 client-fingerprint。上游源多把浏览器指纹写在 fingerprint，
      直接透传会让 mihomo 解析报错并整体退出，这里改名为 client-fingerprint。
    """
    if "fingerprint" in n:
        val = n.pop("fingerprint")
        s = str(val).strip().lower()
        # 证书指纹是长十六进制串（含冒号）；其余视为浏览器指纹
        is_cert_pin = bool(s) and all(c in "0123456789abcdef:" for c in s) and len(s) >= 32
        if not is_cert_pin and "client-fingerprint" not in n:
            n["client-fingerprint"] = val
    return n


def node_fingerprint(n: dict) -> str:
    """节点内容指纹：协议 + 服务器 + 端口 + 凭据。
    不含节点名——同名不同内容、同内容不同名都应视为同一节点。
    """
    import hashlib
    parts = [
        str(n.get("type", "")),
        str(n.get("server", "")),
        str(n.get("port", "")),
        str(n.get("uuid", "") or n.get("password", "") or ""),
        str(n.get("network", "") or ""),
        str(n.get("sni", "") or n.get("servername", "") or ""),
    ]
    return hashlib.md5("|".join(parts).encode("utf-8")).hexdigest()


def dedup_nodes(nodes):
    """按内容指纹去重，保留先出现的；返回 (唯一节点列表, 去重数量)。"""
    seen = {}
    uniq = []
    for n in nodes:
        fp = node_fingerprint(n)
        if fp in seen:
            continue
        seen[fp] = True
        uniq.append(n)
    return uniq, len(nodes) - len(uniq)


def load_nodes(path: str):
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc.get("proxies") or []


def write_conf(nodes, path: str = "alive_conf.yaml"):
    """生成最小 mihomo 配置：只有 proxies + 一个 selector 便于 API 调用。"""
    conf = {
        "mixed-port": 17890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": "127.0.0.1:19090",
        "proxies": nodes,
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [n["name"] for n in nodes]}],
        "rules": ["MATCH,TEST"],
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(conf, f, allow_unicode=True, sort_keys=False)
    return path


def kill_stale_mihomo(binary: str) -> None:
    """清理残留的测试用 mihomo 进程，避免端口被占用导致 API 指向旧实例。"""
    try:
        subprocess.run(["pkill", "-9", "-f", binary], capture_output=True, timeout=10)
        time.sleep(1)
    except Exception:
        pass


def _port_free(port: int) -> bool:
    import socket
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def start_mihomo(binary: str, conf: str, port: int = 19090, mixed: int = 17890):
    kill_stale_mihomo(binary)
    if not _port_free(port):
        raise RuntimeError(f"端口 {port} 被其他进程占用，无法启动测试实例")
    print("启动 mihomo ...", flush=True)
    log = open("mihomo_test.log", "w", encoding="utf-8")
    proc = subprocess.Popen([binary, "-f", conf, "-d", "."],
                            stdout=log, stderr=log)
    for _ in range(40):
        time.sleep(0.5)
        if proc.poll() is not None:
            log.close()
            raise RuntimeError("mihomo 进程提前退出，详见 mihomo_test.log")
        try:
            with urllib.request.urlopen(f"{API}/version", timeout=2) as r:
                if r.status == 200:
                    print("mihomo 就绪", flush=True)
                    return proc
        except Exception:
            continue
    proc.terminate()
    raise RuntimeError("mihomo 启动超时")


def test_one(name: str, url: str, timeout: int) -> int:
    """返回延迟毫秒；失败返回 -1。"""
    q = urllib.parse.urlencode({"url": url, "timeout": timeout})
    api = f"{API}/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}"
    try:
        with urllib.request.urlopen(api, timeout=timeout / 1000 + 5) as r:
            return json.load(r).get("delay", -1)
    except Exception:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=TEST_URL)
    ap.add_argument("--timeout", type=int, default=5000)
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--in", dest="inp", default="snippets/nodes.check.yml")
    ap.add_argument("--out", dest="out", default="snippets/nodes.alive.yml")
    ap.add_argument("--report", default="alive_result.csv")
    args = ap.parse_args()

    nodes = load_nodes(args.inp)
    print(f"载入 {len(nodes)} 个节点（来自 {args.inp}）", flush=True)
    if not nodes:
        print("没有节点，退出"); return 1

    # 修正上游源里的过时字段（如 fingerprint → client-fingerprint），
    # 否则 mihomo 会因单个节点解析失败而拒绝启动
    fixed = 0
    for n in nodes:
        before = "fingerprint" in n
        sanitize_node(n)
        if before:
            fixed += 1
    if fixed:
        print(f"字段修正：{fixed} 个节点的 fingerprint 已转为 client-fingerprint", flush=True)

    # 测活前按内容指纹去重：同一节点可能来自多个源、被起了不同名字
    nodes, removed = dedup_nodes(nodes)
    if removed:
        print(f"去重：移除 {removed} 个重复节点，剩余 {len(nodes)} 个待测", flush=True)
    else:
        print(f"去重：无重复，{len(nodes)} 个待测", flush=True)

    binary = download_mihomo()
    conf = write_conf(nodes)
    proc = start_mihomo(binary, conf)
    try:
        results = {}
        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(test_one, n["name"], args.url, args.timeout): n for n in nodes}
            done = 0
            for fut in cf.as_completed(futs):
                n = futs[fut]
                results[n["name"]] = fut.result()
                done += 1
                if done % 25 == 0 or done == len(nodes):
                    ok = sum(1 for v in results.values() if v > 0)
                    print(f"  进度 {done}/{len(nodes)}  可用 {ok}", flush=True)
    finally:
        proc.send_signal(signal.SIGTERM)
        try: proc.wait(timeout=10)
        except Exception: proc.kill()

    alive = [n for n in nodes if results.get(n["name"], -1) > 0]
    # 按延迟排序，写出去掉 ✅/❌ 前缀的干净名称
    for n in alive:
        n["name"] = n["name"].lstrip("✅❌ ").strip()
    alive.sort(key=lambda n: results[n["name"]] if n["name"] in results else 99999)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(f"# Alive-check: {time.strftime('%Y-%m-%d %H:%M')}  "
                f"可用 {len(alive)}/{len(nodes)}\n")
        yaml.safe_dump({"proxies": alive}, f, allow_unicode=True, sort_keys=False)

    with open(args.report, "w", encoding="utf-8") as f:
        f.write("name,type,server,port,delay_ms,alive\n")
        for n in nodes:
            d = results.get(n["name"], -1)
            nm = n["name"].replace(",", " ")
            f.write(f"{nm},{n.get('type','')},{n.get('server','')},{n.get('port','')},{d},{'yes' if d>0 else 'no'}\n")

    ok = len(alive)
    print(f"\n完成：{ok}/{len(nodes)} 个唯一节点真实可用（延迟测试通过）")
    if removed:
        print(f"  （输入阶段已去除 {removed} 个重复节点）")
    print(f"  输出 {args.out}")
    print(f"  报告 {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
