# 效能與容量報告

> **測量限制先講**：所有數字來自筆電級雲端主機上、**QEMU TCG（純軟體模擬，沒有 KVM）**的 2 vCPU VM。TCG 會把每個指令放大許多倍，絕對值和實體網路設備沒有可比性；這份報告只回答「同一個環境裡，各個方案的**相對**開銷」與「瓶頸在哪」。

## 方法

腳本：[`test/perf/run.sh`](../test/perf/run.sh)，原始資料：[`test/perf/results/2026-11-08/`](../test/perf/results/2026-11-08/)。

| 項目 | 設定 |
|---|---|
| 路徑 | lan-client（10.10.10.10）→ gateway → wan-host（192.0.2.10），經 SNAT |
| 環境 | QEMU TCG，2 vCPU（`QEMU TCG CPU version 2.5+`），2.9 GiB RAM，kernel 6.8.0-147-generic，host 為 Intel Xeon @ 2.10 GHz |
| 吞吐量 | `iperf3` 單一 TCP stream，8 秒 |
| 連線建立速率 | `test/perf/connrate.c`：TCP connect → abortive close 迴圈 5 秒；每條連線都要建立 flow，SNAT 時還要分配 port |
| 重複 | 每個方案先跑一次不記錄的暖機，再 5 次；報告中位數與範圍；兩輪之間等 11 秒讓已關閉的 flow 過期（`tcp_close_timeout` 10 秒） |
| 等價政策 | 同一份意圖：[`test/perf/policy.yaml`](../test/perf/policy.yaml)（v2）、[`test/perf/nftables.nft`](../test/perf/nftables.nft)、原版用 `uapp rule/nat add`（見 run.sh）。SNAT pool 都是 20000–59999 |
| NAT 驗證 | 每個方案都記錄 wan-host 看到的來源位址：baseline 是 `10.10.10.10`（沒有 NAT），其他都是 `192.0.2.1:xxxxx` |

比較的五個方案：

1. **baseline**：模組卸載、沒有 nftables，純路由（沒有過濾、沒有 NAT）。
2. **nftables**：Linux 內建 `nf_conntrack` + nftables 的等價規則與 SNAT。
3. **original**：v1（`main` 分支）的 myfw，同樣規則與 SNAT。
4. **v2-dataplane**：v2 核心模組與政策，但控制面（agent / guard / collector / 每 2 分鐘的探測 timer）停止。
5. **v2**：完整部署，控制面照常運作。

## 結果

| 方案 | TCP 吞吐量 Mbit/s 中位數（範圍） | 相對 baseline | 新連線/秒 中位數（範圍） | 相對 baseline | 失敗連線 |
|---|---|---|---|---|---|
| baseline | 967（890–1074） | — | 1150（976–1308） | — | 0 |
| nftables | 848（778–881） | 88% | 876（845–956） | 76% | 0 |
| original | 960（850–1052） | 99% | 1001（935–1024） | 87% | 0 |
| v2-dataplane | 935（890–956） | 97% | 974（903–1022） | 85% | 0 |
| v2 | 815（720–850） | 84% | 976（457–1044） | 85% | 0 |

同一天較早的另一輪完整測量（沒有 v2-dataplane 這一項）趨勢相同：baseline 1032、nftables 880、original 954、v2 749 Mbit/s。

## 解讀

1. **v2 的資料面和原版幾乎一樣快**（97% vs 99% 吞吐量、85% vs 87% 連線速率，差距在測量範圍內）。v2 多做的事——zone 反偽造、flow 綁介面、每個 hook 檢查 generation、per-CPU 計數、fail-closed 判斷——在這個環境量不出明顯成本。
2. **完整 v2 比 v2-dataplane 慢約 13% 吞吐量**，差別只在控制面有沒有在跑。VM 只有 2 個模擬 vCPU：collector 每 5 秒讀一次核心、verify timer 每 2 分鐘從各 namespace 開 10 條探測連線、guard 每秒心跳，都和 iperf3 搶 CPU。v2 連線速率的最低值（457/s）出現在其中一輪，與探測 timer 觸發時間重疊。**在真實環境，控制面應該和轉發路徑分開的 CPU 上執行**；這是部署上的考量，不是資料面的成本。
3. **nftables 在這裡比 myfw 慢**，主要是 `nf_conntrack` 本身的開銷（完整的 TCP 狀態機、序號視窗檢查、helper、expectation）。myfw 刻意不檢查 TCP 序號（見 README 限制），做的事比較少，**這不代表 myfw 比較好**：nftables 提供的保護與功能多得多，而且在實體硬體與多佇列網卡上的擴展性經過長期驗證。
4. **連線建立速率比吞吐量更敏感**：每條新連線都要跑規則比對、建立 flow、分配 SNAT port，TCG 下每秒約 1000 條。依 `tcp_close_timeout` 10 秒估算，穩定狀態約有 1 萬個 flow 處於關閉中，佔 `max_conns`（16384）的六成以上。這是本 lab 的容量上限，見下一節。

## 容量

| 資源 | 上限 | 用完時的行為 | 測試 |
|---|---|---|---|
| flow 表 | `max_conns`（預設 16384，可線上調整） | 新連線 DROP（`flow_table_full`），既有連線不受影響 | `test_capacity_flow_limit_fails_closed` |
| SNAT port pool | 政策中的 `port_range`（demo 為 1000 個） | 新連線 DROP（`nat_allocation_failed`），不會以內部位址送出 | `test_snat_pool_exhaustion_fails_closed`、[事故報告](incidents/nat-pool-exhaustion.md) |
| 政策大小 | 規則、NAT、zone 數量上限（`include/fw_proto.h`） | validator 與核心都拒絕 | 單元測試、e2e |
| 事件 ring | 1024 筆 | 覆寫最舊的，計數並寫 gap 紀錄 | `test_event_gap_is_recorded` |

粗估：demo 的 1000 個 SNAT port，在每條連線結束後還佔用 10 秒的情況下，可持續支撐約 **100 條新連線/秒**（1000 ÷ 10）對同一個目的位址:port。超過這個速率，`nat_allocation_failed` 會開始增加；調大 pool 或縮短 `tcp_close_timeout` 都是選項，後者要權衡遲到的 FIN/ACK 被丟掉。

## 政策更新時的影響

`test_commits_under_load_never_mix_policies`：三條 HTTPS client 持續發請求，同時連續 commit 20 次（兩份政策交替）：

- gate 時間：中位數 0.55 ms、最大 5.0 ms（TCG；較早一輪 1.9 / 7.7 ms）。在沒有流量的情況下單次 commit 的 gate 約 0.2–0.4 ms。
- 沒有任何回應來自錯誤的服務、沒有任何封包以未轉換的內部位址送出（外部 leak 計數 0）。
- 失敗的請求來自**每次 commit 都會重置既有 flow** 的設計：進行中的 TCP（尤其是 NAT）session 被切斷，client 重試即可。這是目前最主要的取捨，改進方向是 commit 時以新政策重新判斷每個 flow，判斷結果不變的就保留。

## 如何重跑

```bash
git archive main | tar -x -C /opt/myfw/orig          # 原版的原始碼
sudo ORIG_SRC=/opt/myfw/orig test/perf/run.sh          # 約 15 分鐘（TCG）
```

腳本結束時（包括失敗時）一定會恢復受管理的狀態：卸載原版模組、清空 nftables、重新載入 v2、`myfw-boot` 套回最後確認版、啟動控制面，最後重新套用 demo 政策。
