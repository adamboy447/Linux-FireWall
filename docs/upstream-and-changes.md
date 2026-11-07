# 上游來源與修改範圍

## 來源

- 原始設計：RicheyJang 的 **RJFireWall**（Netfilter 核心模組 + Netlink 使用者空間工具）。
- 直接上游：[jujuegg/FireWall](https://github.com/jujuegg/FireWall)，繁中化並移植到 kernel 6.8。
- 本 repo：[adamboy447/Linux-FireWall](https://github.com/adamboy447/Linux-FireWall)。授權維持 **AGPL-3.0**（`LICENSE`），核心模組宣告為 GPL。

## 版本與分支

| 分支 | 內容 |
|---|---|
| `main` | v1：修正原版的正確性與安全問題，加上 QEMU e2e 測試（88 項） |
| `myfw-ops-v2` | v2：政策 snapshot 與原子 commit、fail-closed 資料面、Python 控制面（policy as code、確認 / 自動 rollback、guard、診斷、指標）、Ansible、整合測試、CI、效能對照 |

## v2 新增或重寫的部分

| 範圍 | 檔案 |
|---|---|
| UAPI v3（版本化請求、分頁回應、ABI 大小回報、政策 blob 格式） | `include/fw_proto.h` |
| 政策 snapshot、staging、commit、generation、zone、fail-closed、事件 ring、per-CPU 計數 | `kernel_mod/policy.c stage.c hooks.c conn.c events.c stats.c netlink.c` |
| `uapp --json`、`policy show/export/apply`、整份 commit 的舊指令 | `cmd/` |
| 控制面（schema、validator、compiler、交易、agent、guard、boot、collector、probe、diagnose、lab） | `control/src/myfw_ops/` |
| 部署 | `deploy/ansible/`、`deploy/systemd/` |
| 觀測 | `observability/` |
| 測試 | `control/tests/`、`test/e2e.sh`（v2 段落）、`test/integration/`、`test/perf/`、`test/ci/` |

## v1 對原版的修正（main 分支）


| 原版問題 | 影響 | 修正 |
|---|---|---|
| 連線狀態只認同一方向 | 白名單模式下回應封包被擋，必須自己寫反向規則 | 雙 tuple 連線表，雙向都能查到 |
| 日誌時間用 `ktime_get()`（開機後經過的時間） | 日誌日期顯示錯誤（1970 年附近） | 改用 `ktime_get_real_seconds()` |
| Netlink 沒有檢查權限 | 任何本機使用者都能改防火牆規則 | 要求 `CAP_NET_ADMIN`，並以 socket 的真實 port id 回覆 |
| 封包路徑（softirq）中用 `GFP_KERNEL` 配置記憶體 | 在 atomic context 中睡眠，可能讓核心當掉 | 封包路徑不再配置記憶體（日誌改為環狀緩衝），連線用 `GFP_ATOMIC` |
| 鎖：查到節點就放鎖再使用、讀鎖「升級」成寫鎖、沒有關 BH | use-after-free、紅黑樹損毀、softirq 與 process context 互相死結 | 統一使用 `spin_lock_bh`，整個操作在鎖內完成，只回傳複本 |
| NAT 直接對 `skb->data` 重算 checksum | 非線性 skb（GSO、大封包）資料損毀甚至越界 | `skb_ensure_writable` + `inet_proto_csum_replace*` 增量更新，也能處理 checksum offload |
| 讀 port 時沒確認 header 在線性區 | 可能讀到越界記憶體 | `skb_header_pointer` |
| 連線 key 沒有協定 | 同 port 的 TCP/UDP 被當成同一條連線 | key 加入協定 |
| 刪除 NAT 規則 0 時沒檢查空串列 | NULL pointer 造成核心 oops | 重寫 NAT 規則管理 |
| rmmod 不釋放規則、日誌、連線 | 記憶體洩漏，且 timer 可能在卸載後觸發 | 依序解除 hook、停止 timer、釋放所有資料 |
| 使用者端 request 沒清零、名稱可能沒有 `\0` | 核心讀到垃圾字串 | 使用者端清零，核心端強制結尾 |
| port 只輸入 `80`（不是 `80-80`） | 上限變成未初始化的值 | 支援 `80`、`80-90`、`any`，並檢查範圍 |
| IP 解析接受 256、不檢查格式 | 錯誤 IP 被默默接受 | 使用 `inet_pton` 並驗證 CIDR |
| 測試腳本 port 對不上（8080 vs 8000） | 腳本無法使用 | 修正並可帶參數 |

