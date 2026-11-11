//! PII 出口脱敏（车牌/公司/手机/证件 → 「车牌N」占位符）与反掩码。
//!
//! 2026-11-11 P0-5（F5）：agent-core 直连 /v1/chat 链路（pai/演示助手/用户输入）
//! 此前无车牌级脱敏即发外部 LLM（codex 链由 agentcore-mcp 出口掩码覆盖，不受影响）。
//! 本模块在 llm.rs 的 `sanitize_messages`（出站上下文）与响应返回/流式发射点
//! （回复回显）收口。
//!
//! 与 agentcore-mcp / office_proxy 的 Python 实现同规（P0-2 审计修订版）：
//! - 车牌：省份简称 + 字母 + 可选一位分隔符（·•.・）+ 4-6 位（贪婪 6、无结束
//!   边界检查——与 Python 正则行为逐字对齐，含「长数字串部分命中」边界）
//! - 手机：`(?<!\d)(?:\+?86)?1[3-9]\d{9}(?!\d)`
//! - 证件：`(?<!\d)\d{17}[0-9Xx](?!\d)`
//! - 公司：后缀（有限公司/股份公司/集团/合伙企业，前导 CJK/括号 2-24）+
//!   无后缀供应商字典（~/.pfaix_org_dict.json，≥3 字符）。**字典加载语义与
//!   Python 端有意不同**：Python（mcp_server.py/proxy.py）失败后每次调用重试；
//!   本模块为负缓存 + ORG_DICT_RETRY_SECS=300s 周期重试——代价是字典文件
//!   新建/修复后最迟 5 分钟生效。
//! - 总开关：AGENTCORE_MASK_DISABLE env 或标记文件 ~/.agent-core-mask-off
//!   （与 Python 双通道同款；演示后删文件即恢复）
//!
//! 设计原则（对齐 sanitize_messages 惯例）：只改「发往外部 LLM 的副本」，不改
//! 会话历史存储——历史存原文，每轮出站重掩、回复入库/出站前反掩码。映射表为
//! 进程内全局（token 进程内稳定），写穿 JSON 文件仅供运维观测，进程重启后
//! 重新编号（历史存原文，无跨进程一致性需求）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// 车牌省份简称（与 Python `_PLATE_RE` 逐字一致——28 个，琼/晋/蒙不在其中，
/// 属已知覆盖边界，与既有审计口径保持 parity）
const PROVINCES: &str = "京津沪渝冀豫云辽黑吉苏浙皖闽赣鲁湘鄂粤桂川贵藏陕甘青宁新";
/// 车牌分隔符（P0-2 审计修订：苏E·1A2B3 等写法此前漏脱敏）
const PLATE_SEPS: &str = "·•.・";
const ORG_SUFFIXES: [&str; 4] = ["有限公司", "股份公司", "集团", "合伙企业"];
/// org 字典加载结果（含空表与失败负缓存）的重试间隔——ocr perf·medium 修复：
/// 无字典部署此前每次 mask_text 持全局锁做阻塞 FS 读，探测/应用双扫再翻倍。
const ORG_DICT_RETRY_SECS: u64 = 300;

/// PII 类别（ocr maint·low 修复：替代裸 usize 下标，非法值不可表示）
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PiiKind {
    Car,
    Org,
    Phone,
    Id,
}
impl PiiKind {
    fn idx(self) -> usize {
        self as usize
    }
    /// 穷举 match（ocr maint·low 修复）：token 标签的正确性不再依赖枚举顺序与
    /// KIND_CN 数组顺序的隐式同步——unmask 侧（含 Python _max_idx）按这些
    /// 精确标签匹配，错位会让「手机」被掩成「证件N」并破坏反掩码。
    fn cn(self) -> &'static str {
        match self {
            PiiKind::Car => "车牌",
            PiiKind::Org => "公司",
            PiiKind::Phone => "手机",
            PiiKind::Id => "证件",
        }
    }
}

fn is_plate_body(c: char) -> bool {
    c.is_ascii_digit() || is_plate_letter(c)
}
fn is_plate_letter(c: char) -> bool {
    ('A'..='H').contains(&c) || ('J'..='N').contains(&c) || ('P'..='Z').contains(&c)
}
fn is_org_lead(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c) || matches!(c, '（' | '）' | '(' | ')')
}

/// 总开关（与 Python `_mask_disabled` 同款双通道）。
pub fn disabled() -> bool {
    use std::sync::OnceLock;
    static ENV_OFF: OnceLock<bool> = OnceLock::new();
    if *ENV_OFF.get_or_init(|| {
        std::env::var("AGENTCORE_MASK_DISABLE")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
            .unwrap_or(false)
    }) {
        return true;
    }
    marker_exists()
}
fn marker_exists() -> bool {
    // SCM/提权上下文 USERPROFILE 可能指向 systemprofile → 双路径探测（Python 同款）
    if let Ok(home) = std::env::var("USERPROFILE") {
        if !home.is_empty()
            && std::path::Path::new(&format!("{}\\.agent-core-mask-off", home)).exists()
        {
            return true;
        }
    }
    std::path::Path::new(r"C:\Users\user\.agent-core-mask-off").exists()
}

fn mask_map_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("AGENTCORE_MASK_FILE") {
        if !p.trim().is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    let root = std::env::var("PFAIX_AGENTS_ROOT").unwrap_or_else(|_| r"D:\pfaix_agents".into());
    std::path::Path::new(&root)
        .join("agent_core_chat")
        .join("work")
        .join("pfaix_mask_map.json")
}

struct State {
    map: BTreeMap<String, String>, // 原文 → token
    counters: [u32; 4],
    /// 上次字典加载结果（成功/空表/失败负缓存同形）+ 时间戳；
    /// ORG_DICT_RETRY_SECS 内直接复用 Arc，不重试 FS。
    org_dict: Option<(Arc<Vec<String>>, std::time::Instant)>,
}

static STATE: Mutex<State> = Mutex::new(State {
    map: BTreeMap::new(),
    counters: [0; 4],
    org_dict: None,
});

fn token_for(state: &mut State, kind: PiiKind, val: &str) -> String {
    if let Some(tok) = state.map.get(val) {
        return tok.clone();
    }
    state.counters[kind.idx()] += 1;
    let tok = format!("「{}{}」", kind.cn(), state.counters[kind.idx()]);
    state.map.insert(val.to_string(), tok.clone());
    persist_map(&state.map);
    tok
}

/// 写穿映射文件（运维观测用；失败仅告警不影响脱敏主流程）。
fn persist_map(map: &BTreeMap<String, String>) {
    let path = mask_map_path();
    let json: std::collections::BTreeMap<&str, &str> =
        map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let Ok(body) = serde_json::to_string(&json) else {
        return;
    };
    let res = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!(target: "agent.privacy", "mask map 写穿失败: {}", e);
    }
}

/// 供应商简称字典（≥3 字符、去重、长名优先）。结果 Arc 共享 + 周期门控重试
/// （失败/缺失也负缓存 ORG_DICT_RETRY_SECS，每周期至多一次 FS 读与一条 WARN）。
fn org_dict(state: &mut State) -> Arc<Vec<String>> {
    if let Some((arc, at)) = &state.org_dict {
        if at.elapsed().as_secs() < ORG_DICT_RETRY_SECS {
            return arc.clone();
        }
    }
    let arc = Arc::new(load_org_dict());
    state.org_dict = Some((arc.clone(), std::time::Instant::now()));
    arc
}

fn load_org_dict() -> Vec<String> {
    let path = std::env::var("AGENTCORE_ORG_DICT")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var("USERPROFILE").unwrap_or_default();
            std::path::Path::new(&home).join(".pfaix_org_dict.json")
        });
    let mut names: Vec<String> = Vec::new();
    match std::fs::read_to_string(&path) {
        Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(serde_json::Value::Array(items)) => {
                for it in items {
                    if let Some(s) = it.as_str() {
                        let t = s.trim();
                        if t.chars().count() >= 3 {
                            names.push(t.to_string());
                        }
                    }
                }
            }
            _ => tracing::warn!(target: "agent.privacy", "org dict 形态非数组: {}", path.display()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // 缺省即无字典文件（文档承诺零影响），静默；负缓存由外层周期门控承担
        }
        Err(e) => tracing::warn!(target: "agent.privacy", "org dict 读取失败: {}", e),
    }
    names.sort_by_key(|b| std::cmp::Reverse(b.chars().count()));
    names.dedup();
    names
}

struct OrgSpan {
    start: usize,
    end: usize, // 不含
    text: String,
}

fn org_spans(chars: &[char], dict: &[String]) -> Vec<OrgSpan> {
    let mut spans: Vec<OrgSpan> = Vec::new();
    // ocr perf·low 修复：后缀 char 集合每调用收集一次，不在逐位循环里重分配
    let suffix_sets: Vec<Vec<char>> = ORG_SUFFIXES.iter().map(|s| s.chars().collect()).collect();
    // ① 后缀匹配（前导 CJK/括号 2-24，正则 {2,24} 语义：可用则取满 24，≥2 才成 span）
    for i in 0..chars.len() {
        for sc in &suffix_sets {
            if chars.len() >= i + sc.len() && chars[i..i + sc.len()] == sc[..] {
                let mut run = 0usize;
                while run < 24 && run < i && is_org_lead(chars[i - run - 1]) {
                    run += 1;
                }
                if run >= 2 {
                    let start = i - run;
                    let text: String = chars[start..i + sc.len()].iter().collect();
                    spans.push(OrgSpan { start, end: i + sc.len(), text });
                }
                break; // 同一位置只取第一个命中的后缀
            }
        }
    }
    // ② 字典简称（仅落在既有 span 之外的位置，长名优先）
    for name in dict {
        let nc: Vec<char> = name.chars().collect();
        if nc.is_empty() || nc.len() > chars.len() {
            continue;
        }
        let mut i = 0usize;
        while i + nc.len() <= chars.len() {
            if chars[i..i + nc.len()] == nc[..]
                && !spans.iter().any(|s| i < s.end && i + nc.len() > s.start)
            {
                spans.push(OrgSpan { start: i, end: i + nc.len(), text: name.clone() });
                i += nc.len();
            } else {
                i += 1;
            }
        }
    }
    spans.sort_by_key(|s| s.start);
    spans
}

/// 各匹配器统一返回 (kind, 匹配原文, 消费字符数)。
fn match_plate(chars: &[char], i: usize) -> Option<(PiiKind, String, usize)> {
    let n = chars.len();
    if !PROVINCES.contains(chars[i]) || i + 1 >= n || !is_plate_letter(chars[i + 1]) {
        return None;
    }
    let mut j = i + 2;
    if j < n && PLATE_SEPS.contains(chars[j]) {
        j += 1;
    }
    let body_start = j;
    while j < n && j - body_start < 6 && is_plate_body(chars[j]) {
        j += 1;
    }
    if !(4..=6).contains(&(j - body_start)) {
        return None;
    }
    Some((PiiKind::Car, chars[i..j].iter().collect(), j - i))
}

fn match_phone(chars: &[char], i: usize) -> Option<(PiiKind, String, usize)> {
    let n = chars.len();
    // 前缀 +86 / 86（前邻非数字），随后 1[3-9]\d{9}；裸 1 开头 11 位
    let (p, start_check) = if chars[i] == '+' && i + 3 < n && chars[i + 1] == '8' && chars[i + 2] == '6' {
        (i + 3, i)
    } else if chars[i] == '8' && i + 2 < n && chars[i + 1] == '6' {
        (i + 2, i)
    } else {
        (i, i)
    };
    if start_check > 0 && chars[start_check - 1].is_ascii_digit() {
        return None; // (?<!\d)
    }
    if p >= n || chars[p] != '1' || p + 10 >= n {
        return None;
    }
    if !('3'..='9').contains(&chars[p + 1]) {
        return None;
    }
    for k in (p + 2)..=(p + 10) {
        if !chars[k].is_ascii_digit() {
            return None;
        }
    }
    if p + 11 < n && chars[p + 11].is_ascii_digit() {
        return None; // (?!\d)
    }
    Some((PiiKind::Phone, chars[i..p + 11].iter().collect(), p + 11 - i))
}

fn match_idcard(chars: &[char], i: usize) -> Option<(PiiKind, String, usize)> {
    let n = chars.len();
    if i > 0 && chars[i - 1].is_ascii_digit() {
        return None; // (?<!\d)
    }
    if i + 18 > n {
        return None;
    }
    for k in i..i + 17 {
        if !chars[k].is_ascii_digit() {
            return None;
        }
    }
    let last = chars[i + 17];
    if !(last.is_ascii_digit() || last == 'X' || last == 'x') {
        return None;
    }
    if i + 18 < n && chars[i + 18].is_ascii_digit() {
        return None; // (?!\d)
    }
    Some((PiiKind::Id, chars[i..i + 18].iter().collect(), 18))
}

/// 便宜的 org 后缀存在性预判（避免字典为空且无后缀时白建 span 表）。
fn text_may_have_org_suffix(chars: &[char]) -> bool {
    ORG_SUFFIXES.iter().any(|s| {
        let sc: Vec<char> = s.chars().collect();
        chars.windows(sc.len()).any(|w| *w == sc[..])
    })
}

/// 掩码：有改写返回 Some(新串)（零命中/开关关闭返回 None，供调用方零克隆直通）。
pub fn mask_text(text: &str) -> Option<String> {
    if text.is_empty() || disabled() {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let dict = {
        let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
        org_dict(&mut guard)
    };
    let mut spans = if !dict.is_empty() || text_may_have_org_suffix(&chars) {
        org_spans(&chars, &dict)
    } else {
        Vec::new()
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut changed = false;
    let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
    while i < chars.len() {
        // org span：跳过已被此前长匹配越过的陈旧 span（防御：span 理论上不会
        // 与 plate/phone/id 重叠——span 字符集为 CJK/括号，但字典条目可能含数字）
        while matches!(spans.first(), Some(s) if s.start < i) {
            spans.remove(0);
        }
        if matches!(spans.first(), Some(s) if s.start == i) {
            let span = spans.remove(0);
            let tok = token_for(&mut guard, PiiKind::Org, &span.text);
            out.push_str(&tok);
            i = span.end;
            changed = true;
            continue;
        }
        if let Some((kind, val, len)) = match_plate(&chars, i)
            .or_else(|| match_phone(&chars, i))
            .or_else(|| match_idcard(&chars, i))
        {
            let tok = token_for(&mut guard, kind, &val);
            out.push_str(&tok);
            i += len;
            changed = true;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    if changed { Some(out) } else { None }
}

/// 反掩码：有改写返回 Some(新串)。
pub fn unmask_text(text: &str) -> Option<String> {
    if text.is_empty() || disabled() {
        return None;
    }
    let mut s = text.to_string();
    let mut changed = false;
    {
        let guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
        // 长值优先替换（防「车牌1」是「车牌10」的前缀）
        let mut pairs: Vec<(&String, &String)> = guard.map.iter().map(|(k, v)| (k, v)).collect();
        pairs.sort_by_key(|(_, tok)| std::cmp::Reverse(tok.chars().count()));
        for (real, tok) in pairs {
            if s.contains(tok.as_str()) {
                s = s.replace(tok.as_str(), real);
                changed = true;
            }
        }
    }
    if changed { Some(s) } else { None }
}

/// 便宜的启发式门控：文本是否可能含任一类 PII（供 sanitize_messages 零克隆
/// 直通判定；false negative 会漏掩——故保守取向：含数字即视为可能）。
pub fn may_contain(text: &str) -> bool {
    if disabled() || text.is_empty() {
        return false;
    }
    text.chars().any(|c| PROVINCES.contains(c))
        || ORG_SUFFIXES.iter().any(|s| text.contains(s))
        || text.chars().any(|c| c.is_ascii_digit())
}

/// 递归掩码 JSON 值中的字符串（出站 tool 参数掩码用；键不动）。
pub fn mask_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            if let Some(n) = mask_text(s) {
                *s = n;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(mask_value),
        serde_json::Value::Object(o) => o.iter_mut().for_each(|(_, x)| mask_value(x)),
        _ => {}
    }
}

/// LLM 响应工具入参反掩码（历史/执行侧见原文，LLM 侧只见 token）。
pub fn unmask_tool_calls(mut tcs: Vec<crate::llm::ToolCall>) -> Vec<crate::llm::ToolCall> {
    for tc in tcs.iter_mut() {
        unmask_value(&mut tc.arguments);
    }
    tcs
}

/// LLM 响应整体反掩码（文本 + 工具入参）。
pub fn unmask_response(mut r: crate::llm::LlmResponse) -> crate::llm::LlmResponse {
    if let Some(u) = unmask_text(&r.text) {
        r.text = u;
    }
    r.tool_calls = unmask_tool_calls(r.tool_calls);
    r
}

/// 递归反掩码 JSON 值中的字符串（工具入参还原用；键不动）。
pub fn unmask_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            if let Some(n) = unmask_text(s) {
                *s = n;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(unmask_value),
        serde_json::Value::Object(o) => o.iter_mut().for_each(|(_, x)| unmask_value(x)),
        _ => {}
    }
}

/// 流式反掩码：跨 chunk 的 token 可能被切断，保留「是某 token 真前缀」的尾部
/// 待下一轮拼接（office_proxy 同款问题的 Rust 加固版）。
pub struct StreamUnmasker {
    carry: String,
}

impl StreamUnmasker {
    pub fn new() -> Self {
        Self { carry: String::new() }
    }
    pub fn push(&mut self, chunk: &str) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        self.carry.push_str(chunk);
        let mut s = std::mem::take(&mut self.carry);
        if let Some(u) = unmask_text(&s) {
            s = u;
        }
        // 尾部 holdback：s 的某后缀是已知 token 的真前缀 → 留待下轮
        let hold_chars = {
            let guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
            let mut best = 0usize;
            for tok in guard.map.values() {
                let tc: Vec<char> = tok.chars().collect();
                for k in (1..tc.len()).rev() {
                    if k <= best {
                        break;
                    }
                    let prefix: String = tc[..k].iter().collect();
                    if s.ends_with(&prefix) {
                        best = k;
                        break;
                    }
                }
            }
            best
        };
        if hold_chars > 0 {
            let total = s.chars().count();
            let cut_byte = s
                .char_indices()
                .nth(total - hold_chars)
                .map(|(b, _)| b)
                .unwrap_or(s.len());
            self.carry = s[cut_byte..].to_string();
            s.truncate(cut_byte);
        }
        s
    }
    pub fn flush(&mut self) -> String {
        let s = std::mem::take(&mut self.carry);
        unmask_text(&s).unwrap_or(s)
    }
}

impl Default for StreamUnmasker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    /// 测试环境隔离（ocr 修复）：映射写穿与临时字典均指向 %TEMP% 专用目录——
    /// 此前 cargo test 会把测试语料写进生产路径 D:\pfaix_agents\...\pfaix_mask_map.json，
    /// 且 roundtrip 用例依赖机器上真实 ~/.pfaix_org_dict.json（非自包含）。
    static ENV_INIT: Once = Once::new();

    fn init_env() {
        ENV_INIT.call_once(|| {
            let dir = std::env::temp_dir().join("agent_core_privacy_tests");
            let _ = std::fs::create_dir_all(&dir);
            let map = dir.join("mask_map.json");
            let _ = std::fs::remove_file(&map);
            std::env::set_var("AGENTCORE_MASK_FILE", &map);
            let dict = dir.join("org_dict.json");
            let _ = std::fs::write(
                &dict,
                "[\"江苏理文造纸\",\"理文造纸\",\"苏州天悦环保\",\"天悦环保\",\"舒心环境\",\"苏州新立丰\"]",
            );
            std::env::set_var("AGENTCORE_ORG_DICT", &dict);
        });
    }

    fn mask(s: &str) -> String {
        init_env();
        mask_text(s).unwrap_or_else(|| s.to_string())
    }

    #[test]
    fn plate_variants() {
        for p in ["苏E12345", "苏ED1234", "苏E123456", "苏E·1A2B3", "苏E·12345", "苏A.D1234", "沪C•2B345", "皖P・D6789"] {
            let out = mask(&format!("前缀{}后缀", p));
            assert!(!out.contains(p), "{} 应被掩码，got {}", p, out);
            assert!(out.contains("「车牌"), "got {}", out);
        }
        // 不误伤：双分隔/超短
        for s in ["苏E··12345", "苏E123"] {
            assert_eq!(mask(s), s, "{} 不应命中", s);
        }
    }

    #[test]
    fn phone_variants() {
        for p in ["13812345678", "+8613812345678", "8613812345678"] {
            let out = mask(&format!("联系{}即可", p));
            assert!(!out.contains(p), "{} 应被掩码，got {}", p, out);
        }
        // 长串不误伤
        assert_eq!(mask("单号1234567890123件"), "单号1234567890123件");
    }

    #[test]
    fn idcard_variants() {
        for p in ["320581199001011234", "32058119900101123X", "32058119900101123x"] {
            let out = mask(p);
            assert!(!out.contains(p), "got {}", out);
            assert!(out.contains("「证件"), "got {}", out);
        }
    }

    #[test]
    fn org_suffix_and_roundtrip() {
        let out = mask("苏州新立丰环保科技有限公司进场");
        assert!(out.contains("「公司"), "got {}", out);
        // roundtrip：mask 后 unmask 应还原原文
        let src = "苏E·1A2B3 江苏理文造纸 +8613812345678 32058119900101123X 常熟市雷博尔再生资源有限公司 吨位23.5";
        let m = mask(src);
        let back = unmask_text(&m).unwrap_or_else(|| m.clone());
        assert_eq!(back, src, "roundtrip 失败: {}", m);
    }

    #[test]
    fn stream_unmasker_handles_split_token() {
        // 构造已知映射：掩一个车牌得到 token（形如「车牌N」）
        let tok = mask("苏E99999");
        assert!(tok.starts_with('「') && tok.ends_with('」'), "got {}", tok);
        // 按字符边界从中间切断（「车牌 / N」）
        let tc: Vec<char> = tok.chars().collect();
        let half = tc.len() / 2;
        let a: String = tc[..half].iter().collect();
        let b: String = tc[half..].iter().collect();
        let mut u = StreamUnmasker::new();
        let out1 = u.push(&a);
        let out2 = u.push(&b);
        let out3 = u.push("，今日进场。");
        let joined = format!("{}{}{}", out1, out2, out3);
        assert!(joined.contains("苏E99999"), "流式还原失败: {}", joined);
        assert!(!joined.contains(&tok), "token 未被还原: {}", joined);
    }

    #[test]
    fn unmask_value_recursive() {
        let tok = mask("苏E88888");
        let mut v = serde_json::json!({"plate": tok, "nested": {"list": [tok]}});
        unmask_value(&mut v);
        assert_eq!(v["plate"], "苏E88888");
        assert_eq!(v["nested"]["list"][0], "苏E88888");
    }
}
