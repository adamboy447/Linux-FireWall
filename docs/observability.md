# 可觀測性

## 原則

1. **收集失敗不等於沒有流量。** collector 讀不到核心時，`myfw_*` 流量序列直接**不輸出**，只留 `myfw_collector_up 0`。面板會顯示「沒有資料」，而不是一條掉到 0 的線（`test_collection_failure_is_not_reported_as_zero_traffic`）。
2. **每個封包只有一個最終判決。** `myfw_packets_total{verdict}` 的 accept + drop 就是被管理的封包總數，不會重複計算。
3. **每個 drop 都有原因。** `myfw_drops_total{reason}`，原因對應核心的 `FW_R_*`。
4. **事件遺失要看得到。** 核心 ring（1024 筆）被覆寫、被限速、collector 漏讀，都分別計數，事件檔裡會寫一筆 `{"type": "gap", "lost": N}`。

## 指標

| 指標 | 型別 | 說明 |
|---|---|---|
| `myfw_collector_up` | gauge | 最近一次收集是否成功 |
| `myfw_up`、`myfw_managed`、`myfw_generation` | gauge | 核心可讀、是否受 fwctl 管理、目前 generation |
| `myfw_packets_total{verdict}`、`myfw_bytes_total{verdict}` | counter | 最終判決 |
| `myfw_drops_total{reason}` | counter | 依原因的 drop |
| `myfw_zone_packets_total{zone,verdict}` | counter | 依 ingress 區域（目前 generation 起算） |
| `myfw_new_flows_total{action}`、`myfw_stateful_hits_total` | counter | 新 flow 的規則決策 vs 狀態表命中 |
| `myfw_connections`、`myfw_connection_limit` | gauge | flow 表用量 |
| `myfw_flow_create_failures_total`、`myfw_nat_allocation_failures_total` | counter | fail-closed 事件 |
| `myfw_commits_total`、`myfw_commit_rejected_total`、`myfw_stage_aborted_total` | counter | 核心交易 |
| `myfw_last_gate_seconds`、`myfw_last_commit_timestamp_seconds` | gauge | 最近一次切換 |
| `myfw_changes_total{state}`、`myfw_change_pending`、`myfw_change_deadline_seconds` | counter/gauge | 控制面變更 |
| `myfw_guard_up` | gauge | guard 心跳新鮮 |
| `myfw_service_probe_success{probe,expect}` | gauge | 最近一次存取矩陣探測（`myfw-verify.timer` 每 2 分鐘） |
| `myfw_events_overwritten_total`、`myfw_events_suppressed_total`、`myfw_collector_events_lost_total`、`myfw_collector_gaps_total` | counter | 事件遺失 |

## 檔案

- [`observability/prometheus.yml`](../observability/prometheus.yml)：抓取 `127.0.0.1:9108`。
- [`observability/alerts.yml`](../observability/alerts.yml)：10 條告警（收集中斷、guard 停止、必要服務失敗、變更即將被退回 / 已被退回、flow 表將滿 / 已滿、SNAT pool 耗盡、持續偽造流量、事件遺失）。
- [`observability/alerts_test.yml`](../observability/alerts_test.yml)：告警的單元測試，CI 用 `promtool test rules` 執行。
- [`observability/dashboards/myfw.json`](../observability/dashboards/myfw.json)：Grafana 面板，四個區塊——健康、流量與 drop、容量、變更時間線（commit 以 annotation 標示）。

## 事件日誌

`/var/log/myfw/events-YYYYMMDD.jsonl`，每行一筆（實際輸出）：

```json
{"boot_id": "cdd054f9-...", "dport": 22, "dst": "192.0.2.1", "generation": 37, "ifindex": 5, "kind": "packet", "len": 40, "proto": "tcp", "reason": "rule", "ref": "baseline:deny-ssh-3", "seq": 1998, "sport": 46328, "src": "192.0.2.10", "ts_ns": 1794072536138328490, "type": "event", "verdict": "drop", "zone": "wan", "zone_slot": 5}
{"boot_id": "cdd054f9-...", "first_available_seq": 914, "lost": 476, "reason": "kernel ring overwrote events before they were read", "time": 1794072159.21, "type": "gap"}
```

collector 以序號游標讀取（`/var/lib/myfw-collector/cursor.json`，含 boot_id），重啟不重複；跳號或重開機都寫 gap 紀錄。單檔超過 10 MB 輪替，保留 3 天、總量上限 200 MB（可用環境變數調整）。
