# 政策語意

政策分成兩份檔案，都放在 Git：

- `lab/inventory.yaml`（部署到 `/etc/myfw/inventory.yaml`）：**環境事實**。管理介面與管理服務、每個區域的介面與網段、端點、必要服務探測。換一台機器時改這份。
- `policies/*.yaml`：**業務政策**。誰可以連到哪裡、NAT、預設動作。每條規則都要有 `owner` 與 `reason`。

範例：[`policies/demo.yaml`](../policies/demo.yaml)。

## 處理流程

```
YAML ─► Pydantic schema ─► validator（語意檢查）─► canonical 有效政策 ─► 語意 hash ─► 核心 blob
                                                   = baseline（由 inventory 產生）
                                                   + 業務政策
```

- **schema**：未知欄位直接拒絕（打錯字不會被默默忽略）；只接受 IPv4。
- **baseline**：由 inventory 自動產生、規則 id 以 `baseline:` 開頭，放在業務規則前面：允許 loopback、允許管理來源連管理服務、擋所有區域連管理網段與管理服務、允許本機必要的對外流量。業務政策不能覆蓋它。
- **canonical 與語意 hash**：只保留會影響封包處理的內容。改 `owner`、`reason`、註解不會改變 hash，所以重新套用語意相同的政策是 **no-op**，不會 commit、也不會重置 flow（`test_no_op_reapply_keeps_flows`）。

## 規則怎麼比對

| 欄位 | 語意 |
|---|---|
| `scope` | `ingress`（預設）：從某個區域進來的封包，不論是轉送還是送到本機。`local_out`：本機產生的封包。 |
| `ingress_zone` | 封包進來的區域（由介面決定）。不寫 = 任何區域。 |
| `source` / `destination` | IPv4 CIDR，**以傳送者使用的位址為準**。也就是 DNAT 服務要寫公開位址與公開 port（`192.0.2.1:8443`），不是內部位址。 |
| `protocol` | `tcp` / `udp` / `icmp` / `any`。ICMP 只支援 echo。 |
| `destination_ports` | port 或 `[lo, hi]` 範圍的清單。 |
| `action` | `accept` / `drop`。 |
| `log` | 這條規則的決定寫入事件（受 `event_rate` 限速）。 |

- 每個新 flow 只過濾**一次**，在任何位址改寫之前；之後同一個 flow 的封包（含回應）走狀態表。
- 規則依檔案順序 **first match**；沒有命中就用 `defaults.action`（建議 `drop`）。
- 回應封包不需要反向規則。

## NAT

| 類型 | 必要欄位 | 語意 |
|---|---|---|
| `snat` | `egress_interface`、`to_address`、`port_range` | 從 `ingress_zone` 來、要從 `egress_interface` 出去的流量，來源改成 `to_address`，port 從 pool 分配。pool 用完 → 新連線 DROP（`nat_allocation_failed`），不會「改不了就原樣送出」。 |
| `dnat` | `destination`（/32）、`protocol`、一個 `destination_ports`、`to_address`、`to_port` | 公開位址:port 改成內部位址:port；內部主機看到真實的外部來源。 |

不支援、validator 會直接拒絕的情況：同一個 flow 同時 SNAT 與 DNAT（double NAT）、hairpin NAT、DNAT 到 gateway 自己、DNAT 目標不在任何區域網段、無範圍的 SNAT pool。

## 檢查等級

| 等級 | 意思 | 會不會擋下 |
|---|---|---|
| `error` | 一定錯：未知區域、重複 id、介面不存在、DNAT 目標不可達、出口介面不符 | 會 |
| `unsupported` | 有意義但本防火牆沒實作：重疊網段、double NAT、hairpin NAT、回程不明確 | 會 |
| `danger` | 會削弱主機本身的保護：開放管理網段或管理服務、使用保留區域名稱、區域介面就是管理介面 | 會 |
| `warning` | 合法但可疑：被前面規則完全遮蔽的規則（`shadowed`）、公開了卻被擋的服務 | `defaults.shadowing: error` 時會 |
| `info` | 只有流量測試能證明的事（服務真的能用） | 不會 |

`policies/invalid/` 有 14 個刻意寫錯的政策，每個檔頭寫明預期的錯誤代碼；CI 用 `test/ci/check-policies.sh` 確認每一個都被以正確的代碼拒絕。

## 在核心裡多做的保護（政策沒寫也一定有）

- 反偽造：來源不在該區域 `allowed_sources` 內就丟。
- IPv6 在受管理的區域介面上一律丟（lab 只處理 IPv4，避免 IPv6 成為繞過路徑）。
- IP 分片、ICMP 錯誤訊息、TCP/UDP/ICMP echo 以外的協定、header 截斷都丟並記錄原因。
- 核心收到 blob 時重新驗證所有欄位與 sha256，不信任使用者空間的檢查結果。
