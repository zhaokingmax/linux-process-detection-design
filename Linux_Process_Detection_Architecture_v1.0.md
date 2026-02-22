# Linux进程行为检测系统 - 技术详细设计文档

> **文档版本**: v1.0  
> **状态**: 可直接指导开发  
> **目标**: MITRE ATT&CK v18.1 Linux进程相关检测

---

## 一、总体架构设计

### 1.1 系统架构总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              整体架构图                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        管理平面 (Management Plane)                    │   │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
│  │   │  策略中心    │  │  告警中心    │  │  威胁狩猎    │  │  可视化大屏   │  │   │
│  │   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │   │
│  └──────────┼────────────────┼────────────────┼────────────────┼──────────┘   │
│             │                │                │                │              │
│             │    REST/gRPC   │    Kafka       │    HTTP/WebSocket │              │
│             │                │                │                │              │
└─────────────┼────────────────┼────────────────┼────────────────┼──────────────┘
              │                │                │                │
┌─────────────┼────────────────┼────────────────┼────────────────┼──────────────┐
│             ▼                ▼                ▼                ▼              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      分析平面 (Analytics Plane)                        │   │
│  │                                                                        │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐          │   │
│  │  │  规则引擎      │  │  ML推理服务    │  │  图分析引擎    │          │   │
│  │  │  Sigma/YARA    │  │  ONNX Runtime  │  │  Neo4j+GNN    │          │   │
│  │  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘          │   │
│  └──────────┼───────────────────┼───────────────────┼───────────────────┘   │
└─────────────┼───────────────────┼───────────────────┼───────────────────────┘
              │                   │                   │
              │    Kafka / gRPC  │                   │
              ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       数据平面 (Data Plane) - Agent                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     eBPF Program Layer                              │   │
│  │   Hook Points: execve/fork/exit/ptrace/mmap/prctl/setsid等         │   │
│  │   内核态决策引擎: 白名单降级采集 + 会话树追踪 + 行为计数器          │   │
│  └────────────────────────┬────────────────────────────────────────────┘   │
│                           │ Ring Buffer                                   │
│                           ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                   用户态 Agent (Rust)                                 │   │
│  │   事件消费者 → 进程树/会话树维护 → 特征提取 → ML推理 → MITRE映射  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 核心设计原则

| 原则 | 描述 | 实现方式 |
|------|------|---------|
| **分层决策** | 内核态做快速过滤，用户态做复杂推理 | eBPF评分 → ML推理 → 图分析 |
| **白名单降级** | 白名单进程不停报，而是降级采集 | 区分FULL/REDUCED/MINIMAL模式 |
| **会话树追踪** | 解决double-fork断链问题 | 追踪sid/pgid/ancestor_chain |
| **双轨ML** | 实时检测+离线分析分离 | 在线模型(<10ms) + 离线模型(天级) |
| **自适应采集** | 根据状态动态调整采集策略 | 正常/警戒/攻击三状态机 |

---

## 二、eBPF采集层详细设计

### 2.1 BPF Maps设计

```c
// 1. 进程白名单表 (核心过滤)
struct proc_key {
    u64 exe_inode;
    u64 mount_ns;
};

struct whitelist_entry {
    u8 trust_level;       // 0=黑名单, 1=观察, 2=白名单
    u8 behavior_mode;    // 0=FULL, 1=REDUCED, 2=MINIMAL
    u8 injection_detect; // 0=DISABLED, 1=ACTIVE, 2=ALWAYS_ON
    u8 padding;
};
BPF_HASH(whitelist, struct proc_key, struct whitelist_entry, 65536);
// 内存: ≈1.25MB

// 2. 进程上下文缓存
struct proc_ctx {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 mount_ns;
    u64 exe_inode;
    u64 start_time;
    u64 sid;        // Session ID (新增)
    u64 pgid;       // Process Group ID (新增)
    char comm[16];
};
BPF_HASH(proc_cache, u32, struct proc_ctx, 32768);
// 内存: ≈2MB

// 3. 会话上下文缓存 (新增)
struct session_ctx {
    u64 sid;
    u64 pgid;
    u64 leader_pid;
    u64 start_time;
    u64 ancestor_sid;
};
BPF_HASH(session_cache, u64, struct session_ctx, 16384);
// 内存: ≈640KB

// 4. 行为计数器 (Per-CPU, 无锁)
BPF_PERCPU_HASH(behavior_counter, u64, struct counter, 16384);
// 内存: 32核≈16MB

// 5. Ring Buffer
BPF_RINGBUF(events, 4 * 1024 * 1024);  // 4MB

// 总内存预算: ≈20-25MB
```

### 2.2 eBPF程序核心逻辑

```c
// execve hook - 核心逻辑示例
SEC("tp/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 now = bpf_ktime_get_ns();
    
    // 1. 获取进程上下文
    struct proc_ctx *p = bpf_map_lookup_elem(&proc_cache, &pid);
    if (!p) { /* 读取task_struct填充 */ }
    
    // 2. 查询白名单
    struct whitelist_entry *white = bpf_map_lookup_elem(&whitelist, &key);
    
    // 【关键改动】白名单不再DROP，而是降级采集
    if (white && white->trust_level == TRUST_LEVEL_WHITE) {
        if (white->behavior_mode == MODE_REDUCED) {
            goto check_anomaly;  // 仍检测异常特征
        }
    }
    
check_anomaly:
    // 3. 异常检测
    u32 score = 0;
    if (has_dangerous_args(ctx)) score += rule_weights[DANGEROUS_ARGS_IDX];
    if (check_abnormal_parent(p)) score += rule_weights[ABNORMAL_PARENT_IDX];
    if (check_session_anomaly(p, ctx)) score += rule_weights[SESSION_ANOMALY_IDX];
    
    // 4. 评分决策
    if (score > threshold) {
        // 写入Ring Buffer
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// 会话树追踪 - setsid hook
SEC("tp/syscalls/sys_enter_setsid")
int handle_sys_enter_setsid(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct session_ctx new_sess = {
        .sid = (u64)pid,
        .pgid = (u64)pid,
        .leader_pid = (u64)pid,
        .start_time = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&session_cache, &new_sess.sid, &new_sess, BPF_ANY);
    return 0;
}
```

### 2.3 用户态Agent架构 (Rust)

```rust
pub struct Agent {
    ebpf: Arc<aya::Ebpf>,
    ring_buf: RingBuf,
    process_tree: Arc<ProcessTree>,
    session_tree: Arc<SessionTree>,
    ml_engine: Arc<MlEngine>,
    mitre_mapper: Arc<MitreMapper>,
    alert_processor: Arc<AlertProcessor>,
    transporter: Arc<Transporter>,
    cache: Arc<LevelDbCache>,
}

impl Agent {
    pub async fn run(&self) -> Result<(), Error> {
        let (tx, rx) = mpsc::channel::<SecurityEvent>(10000);
        
        // 启动工作线程
        let ebpf_reader = self.spawn_ebpf_reader(tx.clone());
        let ml_processor = self.spawn_ml_processor(rx);
        let alert_aggregator = self.spawn_alert_aggregator();
        
        tokio::try_join!(ebpf_reader, ml_processor, alert_aggregator)
    }
}
```

---

## 三、ML模型详细设计

### 3.1 ML模型体系架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ML模型体系架构                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      特征提取层 (256维)                              │ │
│  │   进程特征(64) + 行为特征(128) + 上下文特征(64)                   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                      多模型融合层                                      │ │
│  │   ┌────────────┐  ┌────────────┐  ┌────────────┐                │ │
│  │   │ 序列异常   │  │ 命令行NLP  │  │ 进程树GNN │                │ │
│  │   │   LSTM    │  │   CNN+GRU  │  │  GraphSAGE│                │ │
│  │   │  延迟<2ms │  │  延迟<1ms  │  │  延迟<5ms │                │ │
│  │   └──────┬─────┘  └──────┬─────┘  └──────┬─────┘                │ │
│  │          └────────────────┼────────────────┘                        │ │
│  │                           ▼                                         │ │
│  │              加权投票 Ensemble (0.35/0.35/0.30)                   │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                    │                                        │
│                                    ▼                                        │
│  输出: {anomaly_score, confidence, MITRE predictions, attack_chain}   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 模型1: 进程序列异常检测 (LSTM)

```python
class ProcessSequenceDetector(nn.Module):
    def __init__(self, vocab_size=512, embedding_dim=64, hidden_dim=128):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.lstm = nn.LSTM(embedding_dim, hidden_dim, bidirectional=True, num_layers=2)
        self.attention = nn.MultiheadAttention(hidden_dim*2, 4, batch_first=True)
        self.fc_anomaly = nn.Sequential(
            nn.Linear(hidden_dim*2, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)
        pooled = attn_out.mean(dim=1)
        return self.fc_anomaly(pooled)

# 训练配置
TRAINING_CONFIG = {
    'sequence_length': 30,
    'hidden_dim': 128,
    'batch_size': 256,
    'learning_rate': 0.001,
    'target_latency_ms': 2.0,
}
```

### 3.3 模型2: 命令行NLP分析 (CNN+GRU)

```python
class CommandLineDetector(nn.Module):
    def __init__(self, max_bytes=512, embedding_dim=64, num_classes=20):
        super().__init__()
        self.byte_embedding = nn.Embedding(256, embedding_dim)
        self.convs = nn.ModuleList([
            nn.Conv1d(embedding_dim, 128, kernel_size=fs, padding=fs//2)
            for fs in [3, 4, 5]
        ])
        self.bigru = nn.GRU(128*3, 64, bidirectional=True, batch_first=True)
        self.fc_classify = nn.Linear(128, num_classes)
        self.fc_obfuscation = nn.Sequential(nn.Linear(128, 1), nn.Sigmoid())
```

### 3.4 模型3: 进程树GNN分析 (GraphSAGE)

```python
class ProcessTreeGNN(nn.Module):
    def __init__(self, node_features=32, hidden_dim=64, num_layers=3):
        super().__init__()
        self.node_encoder = nn.Linear(node_features, hidden_dim)
        self.convs = nn.ModuleList([SAGEConv(hidden_dim, hidden_dim) for _ in range(num_layers)])
        self.fc = nn.Sequential(nn.Linear(hidden_dim*4, 128), nn.ReLU(), nn.Linear(128, 1), nn.Sigmoid())
    
    def forward(self, data):
        x = self.node_encoder(data.x)
        for conv in self.convs:
            x = F.relu(conv(x, data.edge_index))
        
        # Graph pooling: mean + max + center + attention
        mean_pool = global_mean_pool(x, data.batch)
        max_pool = global_max_pool(x, data.batch)
        return self.fc(torch.cat([mean_pool, max_pool], dim=-1))
```

---

## 四、服务端分层架构

### 4.1 分层架构总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        服务端分层架构                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                      接入层 (API Gateway)                             │ │
│  │   gRPC Ingestion + REST API + WebSocket + Kafka Consumer             │ │
│  └───────────────────────────────┬───────────────────────────────────────┘ │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │               实时处理层 (Real-time Layer) - 轻量                      │ │
│  │   事件归一化(<1ms) + 窗口聚合(<5ms) + 轻量规则(<2ms) + 快速ML(<5ms) │ │
│  │   └────────────────────────────────────────────────────────────┘        │ │
│  │                              │                                         │ │
│  │                              ▼                                         │ │
│  │                    实时告警决策器                                       │ │
│  └───────────────────────────────┬───────────────────────────────────────┘ │
│                                  │                                          │
│                                  │ 事件流                                    │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │               离线分析层 (Offline Layer) - 深度                       │ │
│  │   ┌────────────────────────┐  ┌───────────────────────────────────┐  │ │
│  │   │    自研无监督ML框架    │  │     图分析引擎 (TuGraph可选)       │  │ │
│  │   │    Anomaly Engine     │  │     图数据库 + 图算法              │  │ │
│  │   │  One-Class SVM        │  │     社区检测 + 路径分析            │  │ │
│  │   │  Isolation Forest     │  │     PageRank + GNN推理             │  │ │
│  │   │  AutoEncoder          │  │     攻击链重构                     │  │ │
│  │   │  Clustering           │  │                                   │  │ │
│  │   └────────────────────────┘  └───────────────────────────────────┘  │ │
│  └───────────────────────────────┬───────────────────────────────────────┘ │
│                                  │                                          │
│                                  ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                    存储层 (Storage Layer)                            │ │
│  │   Redis(Hot<1h) + ClickHouse(Warm<7d) + TuGraph(Graph<30d) + S3   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 轻量级流处理引擎

```python
class LightweightProcessor:
    """轻量级流处理引擎 - 目标延迟<10ms"""
    
    async def process_event(self, event: SecurityEvent) -> Option<Alert]:
        start = Instant::now()
        
        # 1. 事件归一化 (<1ms)
        normalized = self.normalize_event(event)
        
        # 2. 窗口聚合更新 (<1ms)
        self.window_aggregator.update(&normalized)
        
        # 3. 规则匹配 (<2ms)
        rule_matches = self.rule_engine.match(&normalized)
        
        # 4. 轻量ML推理 (<5ms)
        ml_result = self.light_ml.predict(&normalized).await
        
        # 5. 告警决策
        alert = self.alert_decision.decide(&normalized, &rule_matches, &ml_result)
        
        # 6. 转发深度层
        if alert.is_suspicious():
            self.forward_to_deep_layer(&normalized).await
        
        return alert
```

### 4.3 轻量ML引擎

```python
class LightMLEngine:
    """轻量ML引擎 - 用于实时检测"""
    
    def __init__(self, model_path: str):
        self.session = ort.InferenceSession(model_path)
        self.feature_extractor = LightFeatureExtractor()
    
    def predict(self, event) -> LightMLResult:
        # 快速特征提取 (<1ms)
        features = self.feature_extractor.extract(event)
        
        # ONNX推理 (<3ms)
        input_tensor = np.array([features], dtype=np.float32)
        output = self.session.run(None, {'input': input_tensor})
        
        return LightMLResult(
            anomaly_score=float(output[0][0]),
            is_anomalous=score > 0.6,
            confidence=abs(score - 0.5) * 2
        )
```

---

## 五、自研无监督ML框架（深度层）

### 5.1 框架架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    自研无监督ML框架 - 架构                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                       异常检测引擎                                      │ │
│  │   One-Class SVM + Isolation Forest + AutoEncoder                    │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                    │                                        │
│                                    ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                       聚类分析引擎                                      │ │
│  │   DBSCAN + K-Means + LOF                                             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                    │                                        │
│                                    ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                       时序分析引擎                                      │ │
│  │   基线建模 + 漂移检测(ADWIN) + 趋势预测(ARIMA)                      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                    │                                        │
│                                    ▼                                        │
│  输出: {anomaly_score, cluster_id, technique_prediction, confidence}       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 核心算法实现

```python
class UnsupervisedMLFramework:
    def __init__(self, config: MLConfig):
        self.scaler = StandardScaler()
        self.one_class_svm = None
        self.isolation_forest = None
        self.autoencoder = None
        self.dbscan = None
        self.kmeans = None
    
    def train(self, data: np.ndarray):
        # 1. 特征缩放
        scaled_data = self.scaler.fit_transform(data)
        
        # 2. 训练One-Class SVM
        self.one_class_svm = OneClassSVM(kernel='rbf', nu=0.1)
        self.one_class_svm.fit(scaled_data)
        
        # 3. 训练Isolation Forest
        self.isolation_forest = IsolationForest(n_estimators=200, contamination=0.1)
        self.isolation_forest.fit(scaled_data)
        
        # 4. 训练AutoEncoder
        self.autoencoder = MLPRegressor(hidden_layer_sizes=(128, 64, 128))
        self.autoencoder.fit(data, data)
        self.config.ae_threshold = np.percentile(errors, 95)
        
        # 5. 聚类分析
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.kmeans = KMeans(n_clusters=10)
    
    def predict(self, data: np.ndarray) -> Dict:
        scaled = self.scaler.transform(data)
        
        # 多模型集成
        svm_score = self.one_class_svm.decision_function(scaled)[0]
        if_score = self.isolation_forest.score_samples(scaled)[0]
        ae_score = self._autoencoder_score(scaled)
        
        # 加权集成
        anomaly_score = 0.3 * svm_norm + 0.4 * if_norm + 0.3 * ae_norm
        
        return {
            'anomaly_score': float(anomaly_score),
            'is_anomalous': anomaly_score > self.config.threshold,
            'confidence': float(confidence),
            'interpretation': self._interpret(anomaly_score)
        }
```

### 5.3 深度特征工程

```python
class DeepFeatureExtractor:
    """深度分析特征提取器 - 256维"""
    
    def extract(self, event, history) -> np.ndarray:
        features = []
        
        # 进程特征 (64维)
        features.extend(self._extract_process_features(event))
        
        # 行为特征 (128维)
        features.extend(self._extract_behavior_features(event, history))
        
        # 上下文特征 (64维)
        features.extend(self._extract_context_features(event, history))
        
        return np.array(features[:256], dtype=np.float32)
```

---

## 六、图分析引擎（TuGraph可选）

### 6.1 图数据模型

```
节点类型:
- Process: pid, exe_path, uid, cmdline, start_time, is_privileged
- File: inode, path, mode, hash
- Network: ip, port, proto
- User: uid, username, gid

边关系:
- spawned_by: 进程父子关系
- opened: 进程打开文件
- connected_to: 进程网络连接
- wrote_to: 进程写入文件
- loaded: 进程加载模块
```

### 6.2 TuGraph集成

```python
class GraphEngine:
    def __init__(self, config):
        self.client = TuGraphClient(url=config.url, user=config.user, password=config.password)
        self._init_schema()
    
    def add_event(self, event: SecurityEvent):
        # 添加进程节点
        self.client.upsert_vertex('Process', {'pid': event.pid, 'exe_path': event.exe_path, ...})
        
        # 添加父子关系
        if event.ppid > 0:
            self.client.insert_edge('Process', event.pid, 'Process', event.ppid, 'spawned_by', {...})
    
    def find_attack_path(self, suspicious_pid: int) -> List[Dict]:
        """攻击路径溯源"""
        query = """
        MATCH path = (suspicious)<-[:spawned_by*1..10]-(ancestor)
        RETURN path ORDER BY length(path) DESC LIMIT 20
        """
        return self.client.exec(query, {'pid': suspicious_pid})
```

---

## 七、两层协同机制

### 7.1 事件协同流转

```
轻量实时层                    深度离线层
    │                           │
    │  事件检测                 │
    │  ├─ 规则命中?             │
    │  ├─ ML分数>0.7?          │
    │  └─ 聚合异常?            │
    │       │                   │
    │      YES                  │
    │       │                   │
    │       ▼                   │
    │  转发到深度层 ──────────▶│
    │                           │
    │                    ┌──────▼──────┐
    │                    │ 深度分析    │
    │                    │ - 无监督ML  │
    │                    │ - 图分析    │
    │                    │ - 攻击链    │
    │                    └──────┬──────┘
    │                           │
    │  规则/模式回注 ◀──────────┤
    │                           │
    ▼                           ▼
最终告警输出 = 轻量即时告警 + 深度溯源
```

### 7.2 双向通信

```python
class LayerCoordination:
    def forward_to_deep(self, event, reason):
        """转发事件到深度层"""
        self.to_deep.send('events.to.deep', key=str(event.pid), value=json.dumps({
            'event': event.to_dict(),
            'reason': reason,
            'light_analysis': {...}
        }))
    
    def register_new_rule(self, rule):
        """规则回注"""
        self.to_light.send('rules.to.light', key=rule['id'], value=json.dumps({
            'type': 'new_rule',
            'rule': rule
        }))
```

---

## 八、MITRE ATT&CK映射引擎

```python
class MitreMapper:
    def _build_technique_rules(self):
        return {
            'T1059.004': {
                'name': 'Unix Shell',
                'tactic': 'TA0002',
                'rules': [{'syscall': 'execve', 'condition': 'exe ~sh|bash|zsh'}],
                'severity': 'HIGH'
            },
            'T1055.008': {
                'name': 'Ptrace System Calls',
                'tactic': 'TA0004',
                'rules': [{'syscall': 'ptrace', 'request': 'PTRACE_POKEDATA'}],
                'severity': 'HIGH'
            },
            # ... 更多规则
        }
    
    def map(self, event):
        results = []
        for tech_id, spec in self.technique_rules.items():
            confidence = self._evaluate_rules(event, spec['rules'])
            if confidence > 0:
                results.append({...})
        return sorted(results, key=lambda x: x['confidence'], reverse=True)
```

---

## 九、存储分层设计

| 层级 | 存储技术 | 数据保留 | 用途 |
|------|---------|---------|------|
| **Hot** | Redis | 1小时 | 实时进程上下文、IOC缓存 |
| **Warm** | ClickHouse | 7天 | 实时查询、结构化分析 |
| **Graph** | TuGraph | 30天 | 进程行为图谱、溯源 |
| **Cold** | S3/OSS | 90天+ | 原始日志归档 |

---

## 十、部署配置

### 10.1 Kubernetes部署

| 组件 | CPU | Memory | Storage | Replicas |
|------|-----|--------|--------|---------|
| Agent (per host) | 0.5 core | 50MB | - | DaemonSet |
| Lightweight Processor | 2 cores | 2GB | - | 3-10 (HPA) |
| Deep Analysis | 8 cores | 16GB | 50GB | 2-4 |
| TuGraph | 4 cores | 8GB | 100GB | 1 |
| ClickHouse | 8 cores | 32GB | 500GB | 3 |
| Redis | 2 cores | 8GB | 10GB | 3 |
| Kafka | 4 cores | 8GB | 100GB | 3+ |

---

## 十一、性能指标

### 11.1 分层性能目标

| 层级 | 指标 | 目标 |
|------|------|------|
| **Agent** | CPU开销 | <2% |
| **Agent** | 内存 | <50MB |
| **轻量实时层** | 端到端延迟 | <10ms |
| **轻量实时层** | 吞吐量 | 50K events/s |
| **深度离线层** | 分析延迟 | <30s |
| **深度离线层** | 图查询延迟 | <50ms |

---

## 十二、开发计划

### Phase 1: 基础能力 (0-3月)

| Week | 任务 |
|------|------|
| 1-2 | eBPF框架搭建 |
| 3-4 | 核心Hook实现 |
| 5-6 | 用户态Agent基础 |
| 7-8 | 进程树维护 |
| 9-10 | 规则引擎集成 |
| 11-12 | 基础MITRE映射 |

### Phase 2: ML能力 (3-6月)

| Week | 任务 |
|------|------|
| 13-14 | 命令行ML模型训练 |
| 15-16 | 序列异常ML模型 |
| 17-18 | 进程树GNN |
| 19-20 | 模型集成 |
| 21-22 | 离线分析层 |
| 23-24 | 优化调优 |

### Phase 3: 高级能力 (6-9月)

| Week | 任务 |
|------|------|
| 25-26 | 会话树追踪 |
| 27-28 | v18.1新增覆盖 |
| 29-30 | 图分析引擎 |
| 31-32 | 威胁狩猎 |
| 33-36 | 集成测试 |

---

## 附录

### A. eBPF Hook完整列表

```c
// 进程相关
SEC("tp/syscalls/sys_enter_execve")
SEC("tp/syscalls/sys_enter_clone")
SEC("tp/syscalls/sys_enter_setsid")
SEC("tp/syscalls/sys_enter_setpgid")
SEC("tp/syscalls/sys_enter_ptrace")
SEC("tp/syscalls/sys_enter_prctl")
SEC("tp/syscalls/sys_enter_mmap")
SEC("tp/syscalls/sys_enter_mprotect")

// 新增Hook
SEC("kprobe/sys_setxattr")
SEC("kprobe/sys_getxattr")
SEC("kprobe/sys_mount")
SEC("tp/syscalls/sys_enter_bpf")
SEC("kprobe/pam_authenticate")
```

### B. MITRE ATT&CK v18.1覆盖

| Tactic | Techniques | 覆盖率 |
|--------|-----------|--------|
| Execution | 10 | 80% |
| Persistence | 18 | 67% |
| Privilege Escalation | 12 | 75% |
| Defense Evasion | 26 | 58% |
| Credential Access | 15 | 53% |
| Discovery | 26 | 58% |
| **总计** | **180+** | **~55%** |

---

> **文档结束** - 可直接指导开发
