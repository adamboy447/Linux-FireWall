# 事故報告：錯誤政策被自動退回

> 在 lab VM 中重現（`2026-11-08 02:16`，kernel 6.8.0-147）。以下輸出皆為實際紀錄，原始檔：`/var/lib/myfw-tests/incidents/wrong-policy.txt`。

## 摘要

操作者「整理規則」時誤刪了 `lan-dmz-web`（內部使用者連 DMZ HTTPS 服務的唯一規則）。政策在語法與語意上都合法，所以通過了 validate。commit 後 agent 立刻從各端點實際連線探測，`lan-to-dmz-https` 失敗，**同一個 `apply` 指令內**就自動套回最後確認版。服務中斷時間約 10 秒（commit 到 rollback commit），操作者不需要任何手動復原動作。

| 項目 | 內容 |
|---|---|
| 影響 | 內部 → DMZ HTTPS 中斷約 10 秒；commit 時重置了 6 個既有 flow |
| 偵測 | 必要服務探測（10 個中 1 個失敗） |
| 復原 | 自動，`fwctl apply` exit 4 |
| 資料面一致性 | 兩次 commit 都是整份切換（generation 6 → 7），沒有半套狀態 |

## 時間線

| 時間 | 事件 |
|---|---|
| 02:16:23 | `fwctl diff /tmp/broken.yaml` 已顯示 `- rule lan-dmz-web`（警告被忽略） |
| 02:16:29 | `fwctl apply`：commit generation 6，gate 0.246 ms，6 個 flow 重置 |
| 02:16:29–38 | 10 個必要服務探測；`lan-to-dmz-https` 逾時 |
| 02:16:38 | 自動 rollback：最後確認版 `d09d394b` 以 generation 7 commit |
| 02:16:42 | 內部 → DMZ HTTPS 恢復 |

## 證據

```
$ fwctl diff /tmp/broken.yaml
active d09d394b99f1fdb9 -> candidate 102ec95dca517677
- rule lan-dmz-web
! committing resets every tracked flow (new generation); translated (NAT) TCP sessions do not survive

$ fwctl apply /tmp/broken.yaml
chg-20261108-021629-19f67e: committed generation 6 (gate 0.246 ms, 6 flow(s) reset)
  FAIL lan-to-dmz-https: expected allow, got timeout
  PASS lan-to-wan-https-snat: expected allow, got connected (server saw 192.0.2.1:20565)
  PASS wan-published-https: expected allow, got connected (server saw 192.0.2.10:50346)
  PASS wan-direct-to-dmz: expected deny, got timeout
  ...（其餘 6 個拒絕探測皆 PASS）
ROLLED BACK to d09d394b99f1fdb9 as generation 7: required service check failed: lan-to-dmz-https (by root)
exit=4

$ fwctl history --limit 3
chg-20261108-021629-19f67e  2026-11-08 02:16:29  rolled_back gen 6  102ec95dca51  root: tidy up rules (mistake: removes internal access)
chg-20261108-021559-256f28  2026-11-08 02:15:59  confirmed   gen 5  d09d394b99f1  root: Internal and simulated external users reach DMZ HTTPS through defined paths

$ fwctl status
generation      7  hash d09d394b99f1fdb9  label rollback-20261108-021629-19f67e
managed         yes; in sync with fwctl: yes
last confirmed  d09d394b99f1fdb9
```

## 根因

1. **直接原因**：手動編輯 YAML 時刪錯規則。
2. **為什麼沒在套用前被擋下**：刪除一條允許規則在語意上是合法的（政策只是變得更嚴格），validator 不會也不應該阻止；`diff` 有列出刪除，但沒有和「必要服務」關聯起來。
3. **為什麼影響很短**：必要服務清單在 inventory 裡，與業務政策分開管理；apply 一定先探測、失敗就退回，不依賴操作者記得檢查。

## 這次的設計重點

- rollback 是**新的 generation**，不是倒轉指標：核心只有一條切換路徑，紀錄與計數單調遞增。
- 被退回的變更留在 history 裡，原因（哪個探測失敗）可追溯。
- 若操作者在探測期間斷線，guard 仍會在 deadline 到期時退回；若當下 agent 被殺，guard 一樣能完成（`test_agent_crash_does_not_stop_the_data_plane_or_the_guard`）。

## 避免再次發生

| 行動 | 狀態 |
|---|---|
| `diff` 標示「這個刪除會影響哪些必要服務」（以 diagnose 的預測邏輯推算） | 待辦 |
| 在 CI 對 PR 中的政策跑離線預測：每個必要服務探測在新政策下的預期結果 | 待辦 |
| 縮短探測逾時以減少中斷時間（目前每個 TCP 探測 2 秒） | 評估中：太短會在負載高時誤判 |
