# -*- coding: utf-8 -*-
"""P0-2 脱敏覆盖度审计 harness（2026-11-11，PFAiX 数据安全分级方案 §六 P0-2）

对两份出口脱敏实现（agentcore-mcp 与 office_proxy）做同规实测：

  T1 车牌覆盖   标准 5 位 / 字母混合 / 新能源 6 位 / 带分隔符（·•.）/ 分隔符不吃多位
  T2 公司覆盖   后缀正则（有限公司/股份公司/集团/合伙企业）+ 无后缀供应商简称字典
  T3 手机覆盖   裸 11 位 / +86 前缀 / 86 前缀 / 长数字串不误伤
  T4 证件覆盖   18 位纯数字 / 尾号 X / 尾号 x
  T5 roundtrip mask→unmask 无损还原（含 dict 命中条目）
  T6 开关双态   标记文件存在=直通（演示态）；删除=脱敏（生产态）
  T7 越界防护   office_proxy mask_file 必须 AGENTS_ROOT 内，越界即拒
  T8 生产核查   当前标记文件 / env 状态（审计留证）

运行：python test_mask_audit.py [--json 结果.json]
退出码：全过=0，有 FAIL=1（供送审附件引用）。
"""
import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MCP_PATH = r"C:\Users\user\agent-core\plugins\agentcore-mcp\mcp_server.py"
PROXY_PATH = r"C:\Users\user\office_proxy\proxy.py"
MARKER = os.path.join(os.path.expanduser("~"), ".agent-core-mask-off")
MARKER_ABS = r"C:\Users\user\.agent-core-mask-off"


def _import(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Audit:
    def __init__(self):
        self.rows = []          # (编号, 用例, 期望, 实测, 判定)
        self.fail = 0

    def check(self, tid, case, ok, got=""):
        self.rows.append((tid, case, "PASS" if ok else "FAIL", got))
        if not ok:
            self.fail += 1

    def report(self):
        w = max(len(r[1]) for r in self.rows) + 2
        for tid, case, verdict, got in self.rows:
            line = "%-4s %-*s %s" % (tid, w, case, verdict)
            if got and verdict == "FAIL":
                line += "  ← %s" % got
            print(line)
        total = len(self.rows)
        print("\n合计 %d 项：PASS %d / FAIL %d" % (total, total - self.fail, self.fail))
        return self.fail


# ── L4 语料（真实格式 + 平台真实供应商名单；具体号码/证件号为构造值） ──
PLATES_HIT = ["苏E12345", "苏ED1234", "苏E123456", "苏E·1A2B3", "苏E·12345",
              "苏A.D1234", "沪C•2B345", "皖P・D6789"]
PLATES_MISS_OK = ["苏E··12345", "苏E123"]            # 双分隔/超短：本就不该命中
ORGS_SUFFIX = ["苏州新立丰环保科技有限公司", "苏州恒星城环境科技有限公司",
               "常熟市雷博尔再生资源有限公司", "常熟市东升再生资源有限公司",
               "某（常熟）有限公司", "某某集团"]
ORGS_DICT = ["江苏理文造纸", "理文造纸", "苏州天悦环保", "天悦环保", "舒心环境",
             "苏州新立丰", "新立丰", "中法水务", "力合环境", "苏再投", "隆力奇"]
PHONES_HIT = ["13812345678", "+8613812345678", "8613812345678"]
PHONES_MISS_OK = ["1234567890123", "1381234567"]     # 13 位长串/10 位短串：不误伤
IDS_HIT = ["320581199001011234", "32058119900101123X", "32058119900101123x"]
TOKEN_RE = None  # 运行时编译：「(车牌|公司|手机|证件)N」


def _leak_check(mask_fn, samples, kind):
    """对每个样本：掩码后输出里不得再出现原文。返回漏脱敏列表。"""
    leaks = []
    for s in samples:
        out = mask_fn("前缀%s后缀" % s)
        if s in out:
            leaks.append(s)
    return leaks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()

    mcp = _import("acm_audit", MCP_PATH)
    proxy = _import("opx_audit", PROXY_PATH)
    global TOKEN_RE
    TOKEN_RE = __import__("re").compile(r"「(车牌|公司|手机|证件)\d+」")

    a = Audit()
    tmp = tempfile.mkdtemp(prefix="mask_audit_")
    mcp_map = os.path.join(tmp, "mcp_map.json")
    # office_proxy 的 mask_file 有 AGENTS_ROOT 越界防护（T7 实证项）——
    # 测试映射必须按真实约定放 <AGENTS_ROOT>/<tag>/work/ 下，用专用 tag 隔离
    proxy_home = os.path.join(proxy.AGENTS_ROOT, "mask_audit_tag")
    os.makedirs(os.path.join(proxy_home, "work"), exist_ok=True)
    proxy_map = os.path.join(proxy_home, "work", "pfaix_mask_map.json")
    if os.path.exists(proxy_map):
        os.remove(proxy_map)
    os.environ["AGENTCORE_MASK_FILE"] = mcp_map

    marker_existed = os.path.isfile(MARKER) or os.path.isfile(MARKER_ABS)
    stash = None
    try:
        # T8 生产核查（进结果留证）
        a.check("T8", "生产状态：脱敏开关标记文件", True,
                "存在（脱敏关闭中）" if marker_existed else "不存在（脱敏开启）")
        if marker_existed:
            stash = MARKER if os.path.isfile(MARKER) else MARKER_ABS
            shutil.move(stash, stash + ".audit_bak")
        # 此处起：开关=生产态（脱敏开启），env 未设

        # T1 车牌
        for name, mod in (("agentcore-mcp", mcp), ("office_proxy", proxy)):
            mf = mcp_map if name.startswith("agentcore") else proxy_map
            fn = (lambda t, _mf=mf, _m=mod: _m.mask_text(t, _mf)) if name == "office_proxy" \
                else (lambda t, _m=mod: _m.mask_text(t))
            leaks = _leak_check(fn, PLATES_HIT, "CAR")
            a.check("T1", "%s 车牌命中（含·•.・/新能源）" % name, not leaks, leaks)
            for s in PLATES_MISS_OK:
                out = fn("前缀%s后缀" % s)
                a.check("T1", "%s 车牌不误伤 %s" % (name, s),
                        ("「车牌" not in out), out)

        # T2 公司
        for name, mod in (("agentcore-mcp", mcp), ("office_proxy", proxy)):
            mf = mcp_map if name.startswith("agentcore") else proxy_map
            fn = (lambda t, _mf=mf, _m=mod: _m.mask_text(t, _mf)) if name == "office_proxy" \
                else (lambda t, _m=mod: _m.mask_text(t))
            leaks = _leak_check(fn, ORGS_SUFFIX + ORGS_DICT, "ORG")
            a.check("T2", "%s 公司命中（后缀正则+简称字典）" % name, not leaks, leaks)
            # 字典整名优先：完整后缀名不得被拆成两段（「苏州天悦环保」+「科技…」）
            out = fn("苏州天悦环保科技有限公司进场")
            a.check("T2", "%s 后缀整名不被字典截断" % name,
                    out.count("「公司") == 1, out)

        # T3 手机
        for name, mod in (("agentcore-mcp", mcp), ("office_proxy", proxy)):
            mf = mcp_map if name.startswith("agentcore") else proxy_map
            fn = (lambda t, _mf=mf, _m=mod: _m.mask_text(t, _mf)) if name == "office_proxy" \
                else (lambda t, _m=mod: _m.mask_text(t))
            leaks = _leak_check(fn, PHONES_HIT, "PH")
            a.check("T3", "%s 手机命中（裸/+86/86）" % name, not leaks, leaks)
            for s in PHONES_MISS_OK:
                out = fn("单号%s件" % s)
                a.check("T3", "%s 手机不误伤 %s" % (name, s),
                        ("「手机" not in out), out)

        # T4 证件
        for name, mod in (("agentcore-mcp", mcp), ("office_proxy", proxy)):
            mf = mcp_map if name.startswith("agentcore") else proxy_map
            fn = (lambda t, _mf=mf, _m=mod: _m.mask_text(t, _mf)) if name == "office_proxy" \
                else (lambda t, _m=mod: _m.mask_text(t))
            leaks = _leak_check(fn, IDS_HIT, "ID")
            a.check("T4", "%s 证件命中（含X/x尾号）" % name, not leaks, leaks)

        # T5 roundtrip（office_proxy unmask；agentcore-mcp unmask pairs 路径）
        sample = ("苏E·1A2B3 江苏理文造纸 +8613812345678 "
                  "32058119900101123X 常熟市雷博尔再生资源有限公司 计量吨位23.5")
        masked = proxy.mask_text(sample, proxy_map)
        restored = proxy.unmask_text(masked, proxy_map)
        a.check("T5", "office_proxy roundtrip 无损还原", restored == sample,
                "out=%s" % restored)
        leaked = [x for x in (PLATES_HIT[:1] + ORGS_DICT[:2] + PHONES_HIT[:1] + IDS_HIT[:1])
                  if x in masked]
        a.check("T5", "office_proxy 掩码输出零 L4 残留", not leaked, leaked)
        m_masked = mcp.mask_text(sample)
        m_pairs = mcp._load_unmask_map()[1]
        m_restored = mcp.unmask_text(m_masked, m_pairs)
        a.check("T5", "agentcore-mcp roundtrip 无损还原", m_restored == sample,
                "out=%s" % m_restored)

        # T6 开关双态（演示态直通）
        open(stash + ".audit_bak", "w").close() if stash else open(MARKER, "w").close()
        try:
            passthrough = proxy.mask_text("苏E12345 苏州新立丰", proxy_map)
            a.check("T6", "开关关（标记文件在）=直通", "苏E12345" in passthrough, passthrough)
        finally:
            os.remove(stash + ".audit_bak" if stash else MARKER)
        on_again = proxy.mask_text("苏E12345", proxy_map)
        a.check("T6", "开关恢复（标记删）=再脱敏", "苏E12345" not in on_again, on_again)

        # T7 越界防护（office_proxy 专用）
        try:
            proxy.mask_text("x", os.path.join(tmp, "..", "evil.json"))
            a.check("T7", "office_proxy mask_file 越界即拒", False, "未抛异常")
        except ValueError:
            a.check("T7", "office_proxy mask_file 越界即拒", True)
        # 映射文件健壮性：损坏 JSON → 警警并继续（fail-open 检测）
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            f.write("{not-json")
        before = proxy._mask_load(bad)
        a.check("T7", "损坏映射文件→空表+load_failed", before == ({}, True), str(before))
    finally:
        # 终态：确保标记文件保持「不存在」（脱敏开启=F1 修复动作）
        if stash and os.path.isfile(stash + ".audit_bak"):
            os.remove(stash + ".audit_bak")
        if os.path.isfile(MARKER):
            os.remove(MARKER)
        if os.path.isfile(MARKER_ABS):
            os.remove(MARKER_ABS)
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(proxy_home, ignore_errors=True)

    fail = a.report()
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"fail": fail, "marker_existed_before": marker_existed,
                       "rows": a.rows}, f, ensure_ascii=False, indent=1)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
