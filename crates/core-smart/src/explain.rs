use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct NodeScore {
    pub node: String,
    pub score: f64,
    pub latency_score: f64,
    pub success_score: f64,
    pub stability_score: f64,
    pub site_memory_score: f64,
    pub load_score: f64,
    pub preference_score: f64,
    pub cost_score: f64,
    pub cooldown_penalty: f64,
    pub capability_penalty: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChoiceExplain {
    pub group: String,
    pub host: String,
    pub picked: String,
    pub cache_hit: Option<String>,
    pub scores: Vec<NodeScore>,
}
