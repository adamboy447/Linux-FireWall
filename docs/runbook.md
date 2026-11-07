# Runbook

所有指令在防火牆主機上執行。`fwctl` 需要群組 `myfw`（變更）或 `myfw-read`（只讀），不需要 root。

## 部署 / 重建

```bash
git clone -b myfw-ops-v2 https://github.com/adamboy447/Linux-FireWall.git /opt/myfw/src
cd /opt/myfw/src
sudo apt install ansible-core
sudo ansible-playbook -c local -i localhost, deploy/ansible/site.yml -e deploy_policy=policies/demo.yaml
```

playbook 會安裝套件、編譯並安裝模組與 `uapp`、建立 venv 與控制面、systemd 單元、lab namespaces，最後**透過 fwctl** 套用並確認政策。第二次執行應該是 `changed=0`；程式碼或單元有變動時，handler 會重啟常駐程式與 lab 服務（namespace 與介面保留，政策裡的 ifindex 仍有效）。

離線環境：`-e wheelhouse=/path/to/wheels -e install_packages=false`。

## 日常變更

```bash
fwctl validate policies/demo.yaml          # 離線檢查，不碰核心
fwctl diff policies/demo.yaml              # 和線上差什麼；會不會重置 flow
fwctl apply policies/demo.yaml             # commit + 必要服務探測，進入 pending（預設 60 秒）
fwctl confirm chg-20261108-...             # 確認；不確認就自動 rollback
fwctl history                              # 誰、何時、結果
```

| `apply` 結束碼 | 意思 | 下一步 |
|---|---|---|
| 0 | pending（或 no-op） | 自己再驗證一次，然後 `confirm` |
| 2 | 政策不合法 | 看 findings，改 YAML |
| 4 | 已 commit，但必要服務探測失敗，已自動 rollback | `fwctl history` 看哪個探測失敗；`fwctl diagnose` |
| 其他 | `pending`（別人的變更還沒確認）、`guard-down`、`conflict` | 依訊息處理 |

## 緊急 rollback

```bash
fwctl rollback --reason "INC-123 web outage"   # 套用最後確認版（新 generation）
```

agent 掛掉時：guard 仍會在 deadline 到時 rollback。兩個都不在時，可直接用核心介面套回 snapshot：

```bash
sudo uapp policy show                       # 目前 generation、hash、label
sudo systemctl restart myfw-boot            # 重新套用最後確認版
```

## 健康檢查

```bash
fwctl status        # 核心 generation/hash、pending、guard 心跳、in_sync
fwctl verify        # 10 個存取矩陣探測（從各端點 namespace 實際連線）
uapp counters       # 最終判決、drop 原因、失敗計數
uapp conn           # flow 表（NAT 連線會顯示 reply tuple）
fwctl events --since 0 --max 50
curl -s 127.0.0.1:9108/metrics | grep ^myfw_
```

`in_sync: false` 代表核心目前的政策不是 fwctl 記錄的最後確認版（有人用 `--force-legacy` 改了，或 rollback 失敗）——先 `fwctl diff` 再決定 rollback 或重新套用。

## 連線不通時

```bash
fwctl diagnose --from lan-client --to 10.10.20.10 --port 443 --check https
```

輸出分兩部分：

1. **預測**：以目前政策推算這個封包會命中哪條規則、會不會 NAT、從哪個介面出去。
2. **證據**：實際從來源 namespace 連線，同時看核心事件與計數的變化、目標端是否有路由回來、是否有服務在聽。

結論會區分「政策擋掉（並指出規則）」、「政策允許但目標沒有回程路由」、「目標沒有服務在聽」、「正常」；證據不足時會明說無法判定，不猜。

## 常見狀況

| 症狀 | 看哪裡 | 處理 |
|---|---|---|
| 外連大量失敗，`nat_allocation_failed` 增加 | `uapp counters`、告警 `MyfwSnatPoolExhausted` | 見 [incidents/nat-pool-exhaustion.md](incidents/nat-pool-exhaustion.md) |
| `flow_table_full` | `uapp status` 的 flows / max_conns | 確認是否被掃描；必要時調高 `max_conns`（`/sys/module/myfw/parameters/max_conns`） |
| 套用後服務壞了 | `fwctl history`、`fwctl diagnose` | 見 [incidents/wrong-policy-rollback.md](incidents/wrong-policy-rollback.md) |
| 大量 `spoofed_source` | `fwctl events`、zone 計數 | 來源網段設定錯，或真的有偽造流量 |
| `apply` 回 `guard-down` | `systemctl status myfw-guard` | guard 回來之前不能改政策（設計如此） |
| metrics 突然沒有 `myfw_packets_total` | `myfw_collector_up` | 是收集失敗，不是沒流量；看 agent |

## 開機

`myfw-lab` → `myfw-boot` → `myfw-agent` / `myfw-guard` / `myfw-collector`。`/etc/sysctl.d/90-myfw.conf` 讓 forwarding 預設關閉，`myfw-boot` 載入模組並套用最後確認版**之後**才打開 forwarding；開機時若有 pending 變更，會被標為 rolled_back（原因 `rebooted while pending`）。
