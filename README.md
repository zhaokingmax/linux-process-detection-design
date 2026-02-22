# Linux进程行为检测系统 - 技术详细设计文档 (v1.1)

> **文档版本**: v1.1  
> **状态**: 基于Elastic detection-rules优化  
> **目标**: MITRE ATT&CK v18.1 Linux进程相关检测  
> **更新**: 新增GTFOBins检测、ML规则框架、False Positive控制、调查指南机制

---

## 一、总体架构设计

### 1.1 系统架构总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              整体架构图                                     │
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
│  │  │  Sigma/EQL    │  │  ONNX Runtime  │  │  Neo4j+GNN    │          │   │
│  │  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘          │   │
│  │          │                    │                    │                    │   │
│  │  ┌───────▼────────────────────▼────────────────────▼──────────────┐  │   │
│  │  │                    威胁情报与调查指南引擎                         │  │   │
│  │  │    GTFOBins库 + MITRE映射 + False Positive分析 + 调查模板      │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
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
│  │   事件消费者 → 进程树/会话树维护 → 特征提取 → ML推理 → MITRE映射   │   │
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
| **GTFOBins优先** | 基于Elastic经验的实战检测 | 87条GTFOBins利用模式库 |
| **False Positive控制** | 借鉴Elastic的成熟机制 | 白名单+置信度+业务上下文 |

### 1.3 v1.1 新增特性 (对比v1.0)

| 特性 | v1.0 | v1.1 (新增) |
|------|------|-------------|
| GTFOBins检测 | 无 | 87种binaries利用模式 |
| ML规则框架 | 自研 | 兼容Elastic ML Job模式 |
| False Positive | 基础 | 5层FP控制体系 |
| 调查指南 | 无 | 每规则附带调查模板 |
| EQL兼容性 | 无 | 支持EQL查询转换 |
| 规则格式 | 自研 | TOML格式对齐Elastic |

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
    
    // 4. GTFOBins特征检测 (v1.1新增)
    if (check_gtfobins_pattern(p, ctx)) score += rule_weights[GTFOBINS_IDX];
    
    // 5. 评分决策
    if (score > threshold) {
        // 写入Ring Buffer
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// GTFOBins特征检测 (v1.1新增)
static __always_inline bool check_gtfobins_pattern(struct proc_ctx *p, struct ctx *ctx) {
    // 检测常见的GTFOBins利用模式
    // 例如: git -> sh, vim -> :!sh, awk -> system(), etc.
    u32 parent_bin_hash = hash_of_parent_bin(p->ppid);
    
    // 查GTFOBins特征表
    struct gtfobins_entry *gtfo = bpf_map_lookup_elem(&gtfobins_map, &parent_bin_hash);
    if (gtfo && gtfo->has_shell_escape) {
        // 检查参数是否匹配利用模式
        return match_gtfo_pattern(ctx->args, gtfo->pattern_mask);
    }
    return false;
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
    gtfobins_detector: Arc<GTFOBinsDetector>,  // v1.1新增
    false_positive_filter: Arc<FalsePositiveFilter>,  // v1.1新增
    investigation_guide: Arc<InvestigationGuideGenerator>,  // v1.1新增
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

## 三、GTFOBins检测模块 (v1.1新增核心特性)

### 3.1 GTFOBins检测架构

基于Elastic 87条Persistence规则的经验，GTFOBins是最常见的Linux权限提升和持久化手段。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        GTFOBins检测模块架构                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    GTFOBins特征库 (87种模式)                        │   │
│  │   ├─ Shell逃逸 (32种): bash, vim, less, more, git, tar, etc.     │   │
│  │   ├─ SUID提权 (25种): nmap, vim, find, etc.                      │   │
│  │   ├─sudo滥用 (18种): apache2, tcpdump, etc.                       │   │
│  │   └─ 内置命令 (12种): awk, sed, perl, python, etc.                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      检测引擎                                        │   │
│  │   1. 进程名+父进程名 组合检测                                     │   │
│  │   2. 命令行参数模式匹配                                            │   │
│  │   3. 父子进程链异常分析                                            │   │
│  │   4. SUID/SGID标志检测                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  输出: {gtfobins_type, technique_id, confidence, MITRE_mapping}           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 GTFOBins特征库

```python
# GTFOBins特征库 - 基于Elastic规则分析
GTFOBINS_LIBRARY = {
    # Shell逃逸类
    "capsh": {
        "patterns": ["--", "--gid", "--uid"],
        "mitre": "T1548.001",
        "technique": "Setuid and Setgid",
        "risk_score": 85
    },
    "git": {
        "patterns": ["!*sh", "exec *sh", "!/bin/sh"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 75
    },
    "vim": {
        "patterns": [":!", ":shell", ":!sh", ":exec"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 80
    },
    "less": {
        "patterns": ["!", "!/bin/sh", "!whoami"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 80
    },
    "find": {
        "patterns": ["-exec", "; /bin/sh", "-exec /*sh"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 75
    },
    "awk": {
        "patterns": ["BEGIN {system", "BEGIN {exec"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 85
    },
    "sed": {
        "patterns": ["-e", "/*sh", "!/bin/sh"],
        "mitre": "T1059.004",
        "technique": "Unix Shell",
        "risk_score": 70
    },
    # SUID提权类
    "nmap": {
        "patterns": ["--interactive", "-v", "--script"],
        "mitre": "T1548.001",
        "technique": "Setuid and Setgid",
        "risk_score": 90,
        "requires_suid": True
    },
    "view": {
        "patterns": ["-c", ":!/*sh"],
        "mitre": "T1548.001",
        "technique": "Setuid and Setgid",
        "risk_score": 85,
        "requires_suid": True
    },
    # sudo滥用类
    "apache2": {
        "patterns": ["-f", "/etc/shadow"],
        "mitre": "T1548.003",
        "technique": "Sudo and Sudo Caching",
        "risk_score": 80
    },
    # 更多模式...
}
```

### 3.3 GTFOBins检测规则示例

```yaml
# GTFOBins检测规则 - 对标Elastic规则
- id: gtfobins_capsh_shell_escape
  name: "GTFOBins: capsh Shell Escape"
  pattern:
    process.name: "capsh"
    process.args: "--"
  parent_patterns:
    - "log4j-cve-2021-44228-hotpatch"  # 白名单
  mitre:
    tactic: "Privilege Escalation"
    technique: "T1548.001"
    subtechnique: "T1548.001"
  risk_score: 85
  severity: "high"
  false_positives:
    - "Container security testing tools"
    - "Legitimate container privilege management"

- id: gtfobins_git_shell_escape
  name: "GTFOBins: git Shell Escape"
  pattern:
    process.name: "bash"
    process.parent.name: "git"
    process.args: "*sh"
  exclude_patterns:
    - "process.parent.args: '!*/sh'"  # 排除git日志操作
    - "process.name: 'ssh'"  # 排除ssh
  mitre:
    tactic: "Execution"
    technique: "T1059.004"
  risk_score: 75
  severity: "medium"
  false_positives:
    - "git hooks for valid workflows"
```

---

## 四、ML模型详细设计

### 4.1 ML模型体系架构

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
│  输出: {anomaly_score, confidence, MITRE predictions, attack │
└_chain}       ─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 模型1: 进程序列异常检测 (LSTM)

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

### 4.3 模型2: 命令行NLP分析 (CNN+GRU)

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

### 4.4 模型3: 进程树GNN分析 (GraphSAGE)

```python
class ProcessTreeGNN(nn.Module):
    def __init__(self, node_features=32, hidden_dim=64, num_layers=3):
        super().__init__()
        self.convs = nn.ModuleList([
            GraphSAGE(node_features, hidden_dim)
            for _ in range(num_layers)
        ])
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
```

### 4.5 ML规则框架 (v1.1新增 - 对标Elastic)

```yaml
# ML检测规则 - 兼容Elastic ML Job模式
ml_rules:
  # 认证异常检测 - 对标Elastic
  - job_id: "v3_linux_rare_metadata_process"
    name: "Unusual Linux Process Calling the Metadata Service"
    anomaly_threshold: 50
    mitre:
      technique: "T1552.005"
      name: "Cloud Instance Metadata API"
    features:
      - process.name
      - process.args
      - user.id
      - cloud.instance.id
    
  # 进程异常检测
  - job_id: "v3_linux_anomalous_process_execution"
    name: "Anomalous Linux Process Execution"
    anomaly_threshold: 75
    features:
      - process.sequence
      - process.parent_relation
      - execution_time
    
  # 网络行为异常
  - job_id: "v3_linux_rare_network_activity"
    name: "Unusual Network Activity from Linux Process"
    anomaly_threshold: 60
    features:
      - network.connection_count
      - network.destination_ports
      - network.bytes_sent

# ML推理服务配置
ml_inference:
  model_format: "onnx"
  max_latency_ms: 10
  batch_size: 32
  fallback_to_rules: true  # ML失败时回退到规则引擎
```

---

## 五、False Positive控制体系 (v1.1新增)

### 5.1 False Positive五层控制架构

基于Elastic 320条Linux规则的false_positives分析，构建五层FP控制体系。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      False Positive 控制体系                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Layer 1: 进程级白名单                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  进程名 + 父进程 + 用户 三元组白名单                                 │   │
│  │  格式: {exe_hash}:{parent_exe}:{uid} → trust_level                  │   │
│  │  示例: /usr/bin/apt:dpkg:0 → FULL_TRUST                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  Layer 2: 参数级白名单                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  基于Elastic规则中的false_positives构建                              │   │
│  │  例如: process.args contains "changelog" → /usr/bin/apt 豁免        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  Layer 3: 上下文白名单                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  容器/K8s/云环境 上下文感知                                         │   │
│  │  例如: container.runtime=docker 且 image=* → 降级阈值              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  Layer 4: 置信度融合                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  多模型投票 + 贝叶斯加权                                             │   │
│  │  规则检测(0.4) + LSTM(0.3) + CNN(0.2) + GNN(0.1)                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  Layer 5: 业务上下文                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  工作时间/非工作时间 + 服务类型 + 地域                              │   │
│  │  例如: DevOps_Server + 03:00 + CN → 降级告警                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 False Positive规则示例

```yaml
# False Positive规则 - 基于Elastic规则分析
false_positive_rules:
  # Cron作业创建 - 基于Elastic persistence_cron_job_creation.toml
  - rule_id: "persistence_cron_job_creation"
    fp_patterns:
      - process.executable: [
          "/bin/dpkg", "/usr/bin/dpkg", "/bin/dockerd",
          "/bin/rpm", "/usr/bin/rpm", "/bin/yum", "/usr/bin/yum",
          "/bin/apt", "/usr/bin/apt", "/bin/pacman"
        ]
      - process.name: ["crond", "executor", "puppet", "chef-client"]
      - file.path: ["/var/spool/cron/crontabs/tmp.*", "/etc/cron.d/jumpcloud-updater"]
      - file.extension: ["swp", "swpx", "swx", "dpkg-remove"]
    
  # Shell逃逸检测
  - rule_id: "gtfobins_shell_escape"
    fp_patterns:
      - process.parent.name: ["log4j-cve-2021-44228-hotpatch"]
      - process.executable: "/var/lib/docker/overlay2/*/merged/bin/busybox"
      - process.parent.args: ["init", "runc", "ls-remote", "push", "fetch"]

  # 系统信息发现
  - rule_id: "discovery_system_info"
    fp_patterns:
      - process.name: ["systemd", "cron", "logrotate"]
      - process.parent.name: ["systemd", "cron"]
```

### 5.3 FP控制决策引擎

```python
class FalsePositiveFilter:
    def __init__(self):
        self.whitelist_db = LevelDB("fp_whitelist")
        self.confidence_weights = {
            'rule': 0.4,
            'lstm': 0.3,
            'cnn': 0.2,
            'gnn': 0.1
        }
    
    def should_alert(self, event: SecurityEvent) -> FilterResult:
        # Layer 1: 进程级白名单检查
        if self.check_process_whitelist(event):
            return FilterResult(suppressed=True, reason="process_whitelist")
        
        # Layer 2: 参数级白名单检查
        if self.check_args_whitelist(event):
            return FilterResult(suppressed=True, reason="args_whitelist")
        
        # Layer 3: 上下文白名单检查
        if self.check_context_whitelist(event):
            return FilterResult(suppressed=True, reason="context_whitelist", 
                               adjusted_score=event.risk_score * 0.5)
        
        # Layer 4: 置信度融合
        confidence = self.calculate_confidence(event)
        if confidence < 0.5:
            return FilterResult(suppressed=True, reason="low_confidence")
        
        # Layer 5: 业务上下文调整
        adjusted_score = self.apply_business_context(event)
        
        return FilterResult(
            suppressed=False,
            final_score=adjusted_score,
            confidence=confidence
        )
```

---

## 六、调查指南生成器 (v1.1新增)

### 6.1 调查指南框架

基于Elastic规则的note字段分析，每个检测规则附带自动化调查指南。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      调查指南生成器架构                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  检测事件                                                                    │
│      │                                                                      │
│      ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  模板匹配引擎                                                          │   │
│  │   ├─ MITRE TTP模板                                                   │   │
│  │   ├─ 攻击阶段模板                                                     │   │
│  │   └─ 工具/技术模板                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│      │                                                                      │
│      ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  上下文注入                                                            │   │
│  │   ├─ 进程树上下文                                                    │   │
│  │   ├─ 网络连接上下文                                                   │   │
│  │   ├─ 文件操作上下文                                                   │   │
│  │   └─ 用户/认证上下文                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│      │                                                                      │
│      ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  调查动作生成                                                          │   │
│  │   ├─ 自动化查询 (Osquery格式)                                        │   │
│  │   ├─ 手工调查步骤                                                     │   │
│  │   └─ 响应建议                                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│      │                                                                      │
│      ▼                                                                      │
│  输出: 结构化调查指南                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 调查指南模板示例

```yaml
# 调查指南模板 - 对标Elastic investigation guide
investigation_templates:
  # Shell逃逸调查模板
  shell_escape:
    title: "Investigating GTFOBins Shell Escape"
    description: |
      Detection alerts from this rule indicate that a Linux utility 
      has been abused to breakout of restricted shells or environments.
    
    investigation_steps:
      - step: 1
        action: "Examine entry point to the host and user"
        query: "session_entry_leader, session_user"
        
      - step: 2
        action: "Examine session leading to the abuse"
        query: "session.commands, session.duration"
        
      - step: 3
        action: "Examine commands executed in spawned shell"
        query: "process.children[].command_line"
        
    false_positive_analysis: |
      - System administration legitimate use of shell commands
      - Container runtime interactions
      - CI/CD pipeline executions
    
    response_actions:
      - "Isolate the involved host"
      - "Terminate suspicious processes"
      - "Block identified IoCs"
      - "Inspect for additional backdoors"

  # Cron持久化调查模板
  cron_persistence:
    title: "Investigating Cron Job Persistence"
    description: |
      Linux cron jobs are scheduled tasks that may be abused for persistence.
    
    investigation_steps:
      - step: 1
        action: "Investigate the cron job file created/modified"
        osquery: |
          SELECT * FROM file WHERE path LIKE '/etc/cron%'
          
      - step: 2
        action: "Investigate process execution chain"
        query: "process.parent_tree"
        
      - step: 3
        action: "Identify user account that performed the action"
        query: "user.authentication_events"
```

---

## 七、规则格式与EQL兼容性 (v1.1新增)

### 7.1 规则格式 - 对标Elastic TOML格式

```toml
# 检测规则示例 - 完全兼容Elastic格式
[metadata]
creation_date = "2024/01/01"
integration = ["endpoint", "linux"]
maturity = "production"
updated_date = "2026/02/22"

[rule]
author = ["Security Team"]
description = """
Detects GTFOBins-based shell escape via capsh binary.
This technique is commonly used for privilege escalation.
"""
from = "now-9m"
index = ["linux-events-*"]
language = "eql"
license = "Proprietary"
name = "GTFOBins: capsh Shell Escape Detection"
risk_score = 85
rule_id = "gtfobins-001-2026"
severity = "high"
tags = [
    "Domain: Endpoint",
    "OS: Linux",
    "Use Case: Threat Detection",
    "Tactic: Privilege Escalation",
    "Technique: GTFOBins",
]
type = "eql"

# EQL查询
query = '''
process where host.os.type == "linux" and event.type == "start" and
  process.name == "capsh" and process.args == "--" and
  not process.parent.executable == "/usr/bin/log4j-cve-2021-44228-hotpatch"
'''

# MITRE ATT&CK映射
[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1548"
name = "Abuse Elevation Control Mechanism"
[[rule.threat.technique.subtechnique]]
id = "T1548.001"
name = "Setuid and Setgid"

[rule.threat.tactic]
id = "TA0004"
name = "Privilege Escalation"

# False Positives
[rule.false_positives]
categories = [
    "Container security tools",
    "Legitimate privilege management"
]

# 调查指南
[rule.investigation]
steps = [
    "Examine parent process chain",
    "Verify if running in container",
    "Check user authentication context"
]
```

### 7.2 EQL到内核事件转换层

```python
class EQLToEBPFRewriter:
    """EQL查询转换为eBPF规则"""
    
    def rewrite(self, eql_query: str) -> List[BPFRule]:
        # 解析EQL查询
        parsed = self.parse_eql(eql_query)
        
        # 转换为eBPF规则
        rules = []
        for condition in parsed.conditions:
            if condition.field == "process.name":
                rules.append(BPFRule(
                    hook="sys_enter_execve",
                    filter=f"ctx->args->filename == \"{condition.value}\""
                ))
            elif condition.field == "process.args":
                rules.append(BPFRule(
                    hook="sys_enter_execve", 
                    filter=self.args_to_filter(condition.value)
                ))
            elif condition.field == "process.parent.name":
                rules.append(BPFRule(
                    hook="sys_enter_execve",
                    filter=f"parent_comm == \"{condition.value}\""
                ))
                
        return rules
```

---

## 八、MITRE ATT&CK v18.1覆盖增强

### 8.1 基于Elastic规则的覆盖矩阵

| Tactic | v1.0 覆盖 | v1.1 新增 | Elastic参考 | 总覆盖率 |
|--------|----------|----------|------------|---------|
| Execution | 80% | +15% | 49条规则 | 95% |
| Persistence | 67% | +20% | 87条规则 | 87% |
| Privilege Escalation | 75% | +15% | 38条规则 | 90% |
| Defense Evasion | 58% | +25% | 53条规则 | 83% |
| Credential Access | 53% | +20% | 19条规则 | 73% |
| Discovery | 58% | +15% | 30条规则 | 73% |
| Lateral Movement | 40% | +20% | 6条规则 | 60% |
| Command and Control | 45% | +15% | 19条规则 | 60% |
| Impact | 50% | +10% | 6条规则 | 60% |
| Initial Access | 30% | +30% | 6条规则 | 60% |
| **总计** | **~55%** | **~20%** | **320条** | **~75%** |

### 8.2 新增覆盖的关键技术

| 技术ID | 技术名称 | 检测方法 | Elastic规则参考 |
|--------|---------|---------|---------------|
| T1059.004 | Unix Shell | GTFOBins + 父子进程分析 | execution_shell_evasion_linux_binary |
| T1548.001 | Setuid and Setgid | SUID检测 + GTFOBins | persistence_bpf_probe_write_user |
| T1053.003 | Cron | 文件监控 + execve | persistence_cron_job_creation |
| T1543.002 | Systemd Service | 文件监控 + systemctl | persistence_systemd_service_creation |
| T1055.004 | APC Injection | kernel_struct监控 | (新增) |
| T1027.004 | Opaque Encoded Data | 字节级CNN | (优化) |
| T1552.005 | Cloud Metadata API | 元数据服务访问监控 | credential_access_ml_linux_anomalous_metadata |

---

## 九、与TOP级EDR厂商对标

### 9.1 能力对比

| 能力维度 | CrowdStrike | SentinelOne | Elastic | 本方案v1.1 |
|---------|------------|------------|---------|----------|
| Agent技术 | eBPF + 内核模块 | eBPF | eBPF (Defend) | eBPF CO-RE (Rust) |
| GTFOBins检测 | 基础 | 基础 | 全面 | 87种模式库 |
| ML检测 | 多模型 | AI引擎 | 44条ML规则 | 5层模型融合 |
| 图分析 | Threat Graph | ✅ | Graph | Neo4j + GNN |
| MITRE覆盖 | >95% | >90% | ~75% | >75% |
| False Positive | <0.1% | <0.1% | 优秀 | 5层控制 |
| 调查指南 | 基础 | 基础 | 完善 | 自动生成 |
| EQL兼容 | ❌ | ❌ | ✅ | ✅ |
| 规则格式 | 私有 | 私有 | TOML | TOML |

### 9.2 差异化优势

1. **GTFOBins专项**: 唯一专注GTFOBins检测的开源方案
2. **EQL兼容**: 兼容Elastic规则生态，降低迁移成本
3. **5层FP控制**: 对标Elastic的成熟FP控制机制
4. **自动化调查**: 每规则附带调查指南模板

---

## 十、开发计划 (更新版)

### Phase 1: 基础能力 (0-3月)

| Week | 任务 |
|------|------|
| 1-2 | eBPF框架搭建 |
| 3-4 | 核心Hook实现 |
| 5-6 | 用户态Agent基础 |
| 7-8 | 进程树维护 |
| 9-10 | 规则引擎集成 |
| 11-12 | 基础MITRE映射 |

### Phase 2: GTFOBins + ML能力 (3-6月)

| Week | 任务 |
|------|------|
| 13-14 | GTFOBins特征库构建 (87种模式) |
| 15-16 | GTFOBins检测规则开发 |
| 17-18 | 命令行ML模型训练 |
| 19-20 | 序列异常ML模型 |
| 21-22 | 进程树GNN |
| 23-24 | ML规则框架 (兼容Elastic) |

### Phase 3: FP控制 + 调查指南 (6-9月)

| Week | 任务 |
|------|------|
| 25-26 | 5层False Positive控制 |
| 27-28 | 调查指南生成器 |
| 29-30 | EQL兼容层 |
| 31-32 | 图分析引擎 (Neo4j) |
| 33-36 | 集成测试 + 优化 |

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

// GTFOBins相关
SEC("kprobe/sys_setxattr")
SEC("kprobe/sys_getxattr")
SEC("kprobe/sys_mount")

// 安全相关
SEC("tp/syscalls/sys_enter_bpf")
SEC("kprobe/pam_authenticate")

// 网络相关
SEC("kprobe/tcp_connect")
SEC("kprobe/udp_sendmsg")
```

### B. GTFOBins完整模式库 (87种)

| 类别 | Binary数量 | 示例 |
|------|-----------|------|
| Shell逃逸 | 32 | capsh, git, vim, less, more, find, awk, sed |
| SUID提权 | 25 | nmap, view, less, vim, vi, find |
| sudo滥用 | 18 | apache2, tcpdump, python, perl |
| 内置命令 | 12 | bash, sh, zsh, ash, dash |

### C. MITRE ATT&CK v18.1覆盖详情

| Tactic | Techniques | 覆盖数 | 覆盖率 |
|--------|-----------|--------|--------|
| Execution | 10 | 9 | 90% |
| Persistence | 18 | 16 | 89% |
| Privilege Escalation | 12 | 11 | 92% |
| Defense Evasion | 26 | 22 | 85% |
| Credential Access | 15 | 11 | 73% |
| Discovery | 26 | 19 | 73% |
| Lateral Movement | 8 | 5 | 63% |
| Command and Control | 16 | 10 | 63% |
| Impact | 13 | 8 | 62% |
| Initial Access | 8 | 5 | 63% |
| **总计** | **180+** | **~135** | **~75%** |

---

> **文档结束** - v1.1版本可直接指导开发
> **主要改进**: GTFOBins检测、ML规则框架、False Positive五层控制、调查指南生成器、EQL兼容性
