#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 CI 中对 nodes.check.yml 的节点做真实代理测活（mihomo 内核）。

与 fetch.py 的 TCP 粗筛不同，这里是协议级测试：
  启动 mihomo → 逐个调用 /proxies/{name}/delay → 延迟测试成功的才是真可用。

用法：
  python alive_check.py [--url URL] [--timeout MS] [--workers N] [--in FILE] [--out FILE]
"""
import argparse
import base64
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



def _strip_none(obj):
    """递归移除值为 None 的项。

    上游源的 YAML 里常出现 `headers: {Host: }`（值为空）这类写法，
    PyYAML 解析成 None；mihomo 要求这些字段是字符串，
    收到 None 会直接 fatal 退出，使整批节点都无法测活。
    """
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(v) for v in obj if v is not None]
    return obj


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
    # 清掉空值字段（如 ws-opts.headers.Host = None）
    cleaned = _strip_none(n)
    n.clear()
    n.update(cleaned)
    return n


def node_invalid_reason(n: dict):
    """校验单个节点能否被 mihomo 正常加载，返回原因字符串；合法则返回 None。

    上游免费源的字段值常不规范，且 mihomo 只要遇到一个节点解析失败就
    fatal 退出，导致整批（数千个）节点都无法测活。此前的做法是"启动失败后
    按报错索引逐个剔除再重试"，虽然有效但很慢——一次启动就要几十秒。
    改为在生成配置前主动校验，把已知类型的坏节点一次性清掉，
    使 mihomo 通常一次即可启动成功。
    """
    # REALITY public-key：mihomo 要求 base64 解码后为 32 字节，否则
    # 报 "invalid REALITY public key" 并拒绝启动。
    ro = n.get("reality-opts")
    if isinstance(ro, dict):
        pk = str(ro.get("public-key", "") or "")
        if not pk:
            return "reality-opts.public-key 缺失"
        try:
            raw = base64.urlsafe_b64decode(pk + "=" * ((4 - len(pk) % 4) % 4))
        except (ValueError, TypeError):
            # 仅把"内容不是合法 base64"判为非法；
            # 不用宽泛的 Exception，避免把 NameError 等编程错误
            # 误判成节点问题（曾因漏 import base64 而误杀 3055 个节点）
            return "reality-opts.public-key 非合法 base64"
        if len(raw) != 32:
            return f"reality-opts.public-key 解码后为 {len(raw)} 字节（应为 32）"
    # ws-opts.headers 必须是 {str: str}
    for key in ("ws-opts", "h2-opts", "grpc-opts", "http-opts"):
        opts = n.get(key)
        if isinstance(opts, dict):
            hdr = opts.get("headers")
            if hdr is not None and not isinstance(hdr, dict):
                return f"{key}.headers 不是字典"
            if isinstance(hdr, dict):
                for hk, hv in hdr.items():
                    if not isinstance(hv, str):
                        return f"{key}.headers[{hk}] 不是字符串"
    return None


def filter_invalid_nodes(nodes, verbose: bool = True):
    """移除 mihomo 无法加载的节点，返回 (合法节点列表, 被移除数)。"""
    good = []
    removed = 0
    reasons = {}
    for n in nodes:
        why = node_invalid_reason(n)
        if why is None:
            good.append(n)
        else:
            removed += 1
            reasons[why] = reasons.get(why, 0) + 1
    if verbose and removed:
        print(f"预校验：剔除 {removed} 个 mihomo 无法加载的节点", flush=True)
        for why, cnt in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"   {cnt:>5} × {why}", flush=True)
    return good, removed


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


def _parse_bad_proxy_index(log_path: str):
    """从 mihomo 日志里解析出错节点的下标。

    典型报错：Parse config error: proxy 1719: filed ws-opts.headers[Host] invalid
    下标是 0-based，与 write_conf() 写入 proxies 的顺序一致。
    """
    import re as _re
    try:
        for line in open(log_path, encoding="utf-8", errors="ignore"):
            m = _re.search(r"Parse config error: proxy (\d+):", line)
            if m:
                return int(m.group(1))
    except OSError:
        pass
    return None


def start_mihomo_resilient(binary: str, nodes, max_drop: int = 40):
    """启动 mihomo；若因个别畸形节点解析失败，则剔除该节点后重试。

    上游免费源的字段质量参差（值为 None、类型不符、拼写错误等），
    只要有一个节点解析失败，mihomo 就会 fatal 退出，导致整批无法测活。
    这里按报错下标逐个剔除，最多剔除 max_drop 个后放弃。

    返回 (proc, nodes)：nodes 是实际写入配置的节点列表（可能已被剔除若干）。
    """
    import re as _re
    dropped = 0
    for _ in range(max_drop + 1):
        write_conf(nodes)
        try:
            return start_mihomo(binary, "alive_conf.yaml"), nodes
        except RuntimeError:
            idx = _parse_bad_proxy_index("mihomo_test.log")
            if idx is None or idx >= len(nodes) or idx < 0:
                raise
            bad = nodes.pop(idx)
            dropped += 1
            label = bad.get("name") if isinstance(bad, dict) else bad
            print(f"  剔除畸形节点 [{idx}] {str(label)[:48]!r}（累计 {dropped} 个）", flush=True)
    raise RuntimeError(f"剔除 {max_drop} 个节点后 mihomo 仍无法启动")


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
    ap.add_argument("--keep-failed", action="store_true",
                    help="不跳过 TCP 粗筛标记为 ❌ 的节点（默认跳过）")
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

    # 主动校验并剔除 mihomo 无法加载的节点（如 REALITY public-key 非法），
    # 避免因单个坏节点导致整批测活失败、进而走"启动失败逐个剔除重试"的慢路径
    nodes, invalid_removed = filter_invalid_nodes(nodes)

    # 跳过 TCP 粗筛已标记为不可达（❌）的节点。
    # nodes.check.yml 的节点名带 ✅/❌ 前缀（fetch.py 的 TCP 粗筛结果），
    # ❌ 表示端口连不上，对其做协议级测活必然超时（每个白等 timeout），
    # 实测 17260 个节点中约 6700 个为 ❌，按并发 32 估算浪费约 17 分钟。
    # 这与本地 SubsCheck 的 filter "^[^❌]" 行为一致。
    # 可用 --keep-failed 关闭该行为（全量测活，用于排查粗筛误判）。
    if not args.keep_failed:
        before_n = len(nodes)
        nodes = [n for n in nodes if not str(n.get("name", "")).startswith("❌")]
        skipped = before_n - len(nodes)
        if skipped:
            print(f"跳过 ❌ 节点 {skipped} 个（TCP 粗筛不可达），"
                  f"剩余 {len(nodes)} 个进入测活", flush=True)

    # 测活前按内容指纹去重：同一节点可能来自多个源、被起了不同名字
    nodes, removed = dedup_nodes(nodes)
    if removed:
        print(f"去重：移除 {removed} 个重复节点，剩余 {len(nodes)} 个待测", flush=True)
    else:
        print(f"去重：无重复，{len(nodes)} 个待测", flush=True)

    binary = download_mihomo()
    proc, nodes = start_mihomo_resilient(binary, nodes)
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

    # 注意：不能用 for n in alive: n["name"]=... 直接改名——那会就地修改 nodes 里的
    # 字典对象，导致随后写 CSV 时用新名字去 results 里查不到（全部误判为 no）。
    # 因此复制出新字典，原 nodes/results 保持以原始名为键。
    alive = []
    for n in nodes:
        if results.get(n["name"], -1) > 0:
            clean = dict(n)
            clean["name"] = str(clean["name"]).lstrip("✅❌ ").strip()
            alive.append((results[n["name"]], clean))
    alive.sort(key=lambda pair: pair[0])
    alive = [c for _, c in alive]

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
