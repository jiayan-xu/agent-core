//! 运行指标层（战略罗盘「持久执行 / 可观测」阶段首个增量）
//!
//! 零行为变化、默认开启、无新 flag：用无锁原子计数器汇总
//! 请求 / LLM 调用 / 错误、各门控特性（TTC 自一致性 / verifier / LATS /
//! MultiAgent / 技能库）实际触发次数、checkpoint 持久执行（保存 / 崩溃恢复）
//! 统计与在途执行 gauge、请求时延（均值 + EWMA）。
//!
//! 通过 `/api/metrics` 暴露快照，使 G 门与 TTC/LATS 投资在生产流量里可观测。

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// 运行指标注册表（所有计数无锁原子；时延 EWMA 用细粒度 Mutex）。
#[derive(Default)]
pub struct MetricsRegistry {
    requests: AtomicU64,
    llm_calls: AtomicU64,
    errors: AtomicU64,
    ttc_activations: AtomicU64,
    ttc_refine_rounds: AtomicU64,
    lats_activations: AtomicU64,
    multiagent_activations: AtomicU64,
    skill_lookups: AtomicU64,
    checkpoint_saves: AtomicU64,
    checkpoint_recoveries: AtomicU64,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
    latency_ewma_ms: Mutex<f64>,
    in_progress: AtomicUsize,
    uptime_start: Mutex<Option<Instant>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        let m = MetricsRegistry::default();
        *m.uptime_start.lock().unwrap() = Some(Instant::now());
        m
    }

    // ── 计数器（无锁） ──
    pub fn inc_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_llm_calls(&self) {
        self.llm_calls.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_ttc(&self) {
        self.ttc_activations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_ttc_refine(&self) {
        self.ttc_refine_rounds.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_lats(&self) {
        self.lats_activations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_multiagent(&self) {
        self.multiagent_activations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_skill(&self) {
        self.skill_lookups.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_checkpoint_save(&self) {
        self.checkpoint_saves.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_checkpoint_recovery(&self) {
        self.checkpoint_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    // ── gauge（在途执行数） ──
    pub fn gauge_in_progress(&self, delta: i64) {
        if delta >= 0 {
            self.in_progress.fetch_add(delta as usize, Ordering::Relaxed);
        } else {
            self.in_progress
                .fetch_sub((-delta) as usize, Ordering::Relaxed);
        }
    }

    // ── 时延（均值 + EWMA） ──
    pub fn record_latency(&self, ms: f64) {
        self.latency_sum_ms.fetch_add(ms as u64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        let mut e = self.latency_ewma_ms.lock().unwrap();
        *e = if *e <= 0.0 { ms } else { 0.8 * *e + 0.2 * ms };
    }

    /// 生成 JSON 快照（features / quota 由 AgentCore 注入，保持单一职责）。
    pub fn snapshot(
        &self,
        features: serde_json::Value,
        quota: serde_json::Value,
    ) -> serde_json::Value {
        let count = self.latency_count.load(Ordering::Relaxed);
        let sum = self.latency_sum_ms.load(Ordering::Relaxed);
        let avg = if count > 0 {
            sum as f64 / count as f64
        } else {
            0.0
        };
        let ewma = *self.latency_ewma_ms.lock().unwrap();
        let uptime = self
            .uptime_start
            .lock()
            .unwrap()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        serde_json::json!({
            "uptime_secs": uptime,
            "features": features,
            "counters": {
                "requests": self.requests.load(Ordering::Relaxed),
                "llm_calls": self.llm_calls.load(Ordering::Relaxed),
                "errors": self.errors.load(Ordering::Relaxed),
                "ttc_activations": self.ttc_activations.load(Ordering::Relaxed),
                "ttc_refine_rounds": self.ttc_refine_rounds.load(Ordering::Relaxed),
                "lats_activations": self.lats_activations.load(Ordering::Relaxed),
                "multiagent_activations": self.multiagent_activations.load(Ordering::Relaxed),
                "skill_lookups": self.skill_lookups.load(Ordering::Relaxed),
                "checkpoint_saves": self.checkpoint_saves.load(Ordering::Relaxed),
                "checkpoint_recoveries": self.checkpoint_recoveries.load(Ordering::Relaxed),
            },
            "gauges": {
                "in_progress_executions": self.in_progress.load(Ordering::Relaxed),
            },
            "latency_ms": {
                "avg": avg,
                "ewma": ewma,
                "count": count,
            },
            "quota": quota,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counters_increment() {
        let m = MetricsRegistry::new();
        m.inc_requests();
        m.inc_llm_calls();
        m.inc_ttc();
        m.inc_lats();
        m.inc_skill();
        m.inc_checkpoint_save();
        let snap = m.snapshot(serde_json::json!({}), serde_json::json!({}));
        assert_eq!(snap["counters"]["requests"], 1);
        assert_eq!(snap["counters"]["llm_calls"], 1);
        assert_eq!(snap["counters"]["ttc_activations"], 1);
        assert_eq!(snap["counters"]["lats_activations"], 1);
        assert_eq!(snap["counters"]["skill_lookups"], 1);
        assert_eq!(snap["counters"]["checkpoint_saves"], 1);
    }

    #[test]
    fn test_gauge_and_latency() {
        let m = MetricsRegistry::new();
        m.gauge_in_progress(2);
        m.gauge_in_progress(-1);
        m.record_latency(100.0);
        m.record_latency(200.0);
        let snap = m.snapshot(serde_json::json!({}), serde_json::json!({}));
        assert_eq!(snap["gauges"]["in_progress_executions"], 1);
        assert_eq!(snap["latency_ms"]["count"], 2);
        // 均值 = (100+200)/2 = 150
        assert_eq!(snap["latency_ms"]["avg"], 150.0);
        // EWMA: 100 → 0.8*100+0.2*200 = 120
        assert!((snap["latency_ms"]["ewma"].as_f64().unwrap() - 120.0).abs() < 1e-6);
    }
}
