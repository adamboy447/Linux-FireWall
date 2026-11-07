# 事故報告：SNAT port pool 耗盡

> 在 lab VM 中刻意重現（`2026-11-08 02:15`，kernel 6.8.0-147，commit 見 test-report）。以下輸出皆為實際紀錄，原始檔：`/var/lib/myfw-tests/incidents/nat-pool.txt`。

## 摘要

一次政策變更把 `lan-outbound` 的 SNAT pool 從 1000 個 port 縮成 4 個（模擬審查時沒注意到的設定錯誤）。變更通過了所有探測並被確認，因為探測只建立一條連線。之後 LAN 同時有 6 個對外 HTTPS session 時，第 5、6 個無法建立。防火牆依設計 **fail closed**：拿不到 port 的連線被丟棄並記錄原因，沒有任何封包以未轉換的內部位址送到外部。重新套用審查過的政策後恢復。

| 項目 | 內容 |
|---|---|
| 影響 | 6 個並行對外連線中 2 個失敗（1 個逾時前只收到 294 KB，1 個完全沒連上） |
| 偵測 | `myfw_drops_total{reason="nat_allocation_failed"}` 增加 → 告警 `MyfwSnatPoolExhausted`；`fwctl diagnose` 直接指出原因 |
| 持續時間 | 從開始到恢復約 50 秒（重現情境） |
| 資料外洩 / 錯誤轉換 | 無（外部主機的 leak 計數器為 0，`test_snat_pool_exhaustion_fails_closed`） |

## 時間線

| 時間 | 事件 |
|---|---|
| 02:15:07 | `fwctl apply`：pool `[20000, 20003]`，generation 4，探測全部通過，確認 |
| 02:15:22 | LAN 端 6 個 client 每 0.3 秒開一個慢速下載（50 KB/s，600 KB） |
| 02:15:31 | flow 表中 4 個 SNAT session 佔滿 20000–20003；`fwctl diagnose` 判定原因 |
| 02:15:48 | `nat_allocation_failed` 累計 20 次（同一連線的 SYN 重傳各計一次） |
| 02:15:59 | 重新套用 `policies/demo.yaml`（1000 port），10/10 探測通過，確認 |
| 02:16:0x | 同樣 6 個並行下載全部成功 |

## 證據

flow 表（`uapp conn`），4 個 port 全被佔用：

```
tcp   10.10.10.10:53644 -> 192.0.2.10:443           SNAT     300s   99/222
      reply: 192.0.2.10:443 -> 192.0.2.1:20003
tcp   10.10.10.10:53646 -> 192.0.2.10:443           SNAT     300s   103/188
      reply: 192.0.2.10:443 -> 192.0.2.1:20000
tcp   10.10.10.10:53648 -> 192.0.2.10:443           SNAT     300s   80/175
      reply: 192.0.2.10:443 -> 192.0.2.1:20001
tcp   10.10.10.10:53652 -> 192.0.2.10:443           SNAT     298s   237/630
      reply: 192.0.2.10:443 -> 192.0.2.1:20002
```

`fwctl diagnose --from lan-client --to 192.0.2.10 --port 443 --check https`：

```
3. prediction: ACCEPT - first match: lan-wan-web; NAT snat lan-outbound -> 192.0.2.1
4. live test: timeout; drop counters moved: {'nat_allocation_failed': 4}
5. destination wan-host: listening=True, route back to 192.0.2.1: yes
6. CONFIRMED: dropped by the firewall for a non-policy reason: nat_allocation_failed
```

政策預測「允許」，但實測失敗，而且失敗期間移動的計數器是 `nat_allocation_failed`——所以不是規則、不是路由、不是服務的問題。

計數與指標：

```
drop 原因增量: {'rule': 6, 'default_policy': 8, 'nat_allocation_failed': 20}
myfw_drops_total{reason="nat_allocation_failed"} 20.0
```

（`rule` / `default_policy` 的增量來自同時段 `fwctl diagnose` 與 verify timer 的拒絕探測，屬於正常背景流量。）

## 根因

1. **直接原因**：SNAT pool 只有 4 個 port，而同時對外的 session 有 6 個。
2. **為什麼變更通過檢查**：validator 只擋「無上限」或格式錯誤的 pool（`snat-unbounded`），沒有容量下限；必要服務探測一次只開一條連線，測不出並行容量。
3. **為什麼恢復有延遲**：session 結束後 port 仍在 `tcp_close_timeout`（10 秒）內被佔用；第 5 個 client 靠 SYN 重傳在約 14 秒後才拿到 port，但已來不及在 20 秒內傳完。

## 修復

- 重新套用審查過的政策（1000 port），10/10 探測通過並確認。
- 這次不需要 rollback：錯誤的變更已經被確認成「最後確認版」，所以修復方式是**再一次正常變更**。這也說明自動 rollback 只保護「確認之前」的時段，確認後的容量問題要靠監控發現。

## 避免再次發生

| 行動 | 狀態 |
|---|---|
| 告警 `MyfwSnatPoolExhausted`（5 分鐘內有任何 `nat_allocation_failed`）與單元測試 | 已完成（`observability/alerts.yml`） |
| Grafana「容量」區塊顯示 fail-closed 事件 | 已完成 |
| validator 新增 `snat-pool-small` warning：pool 小於預期並行 session 數（需要在 inventory 宣告預期容量） | 待辦 |
| 必要服務探測增加「並行 N 條」的容量探測 | 待辦 |
| `diff` 對 pool 縮小顯示明確警告 | 待辦 |
