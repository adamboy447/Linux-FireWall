# 測試報告

| 項目 | 值 |
|---|---|
| 分支 / commit | `myfw-ops-v2` @ `c6ea726`（之後的 commit 只有文件、效能腳本與測試紀錄） |
| 日期 | 2026-11-08 |
| 主機 | Intel Xeon @ 2.10 GHz，2 cores（雲端沙箱，無 KVM） |
| 核心 e2e 的 guest kernel | Ubuntu `6.8.0-147-generic`、`6.17.0-42-generic` |
| 整合測試 VM | Ubuntu 24.04，kernel 6.8.0-147-generic，QEMU TCG 2 vCPU / 3 GB，Ansible 部署 |
| Python | 3.12（VM）；單元測試另在 3.10、3.13 執行 |

## 總覽

| 層級 | 指令 | 數量 | 結果 |
|---|---|---|---|
| 單元測試 | `pytest control/tests` | 46 | 46/46（3.10、3.12、3.13） |
| 政策檢查 | `test/ci/check-policies.sh` | 15 | 全部符合預期（1 合法、14 以正確代碼拒絕） |
| 核心 e2e（6.8） | `KVER=6.8.0-147-generic test/vm/run.sh` | 134 | 134/134 |
| 核心 e2e（6.17） | `KVER=6.17.0-42-generic test/vm/run.sh` | 134 | 134/134 |
| VM 整合測試 | `sudo pytest test/integration`（在部署好的 VM 內） | 26 | 26/26（10 分鐘） |
| pending 中重開機 | `test/integration/reboot_pending.py prepare` → reboot → `check` | 1 | PASS |
| Ansible 冪等 | 同一個 playbook 連跑兩次 | 2 | 第 1 次 `changed=2`（新程式碼 + 重啟 handler），第 2 次 `changed=0` |
| GitHub Actions CI | `.github/workflows/ci.yml` | 5 jobs | 全部通過（單元測試 3.10 / 3.12、告警測試、`-Werror` 編譯、runner 上 KVM 的 QEMU e2e） |
| 開機還原 | VM 非正常停止後重新開機 | 1 | `myfw-boot` 套用最後確認版（label `boot-restore`），之後才開 forwarding |

原始紀錄：`test/results/e2e-kernel-*.log`、`test/results/integration.log`。

## 單元測試（`control/tests`）

- **ABI 交叉比對**：用 C 編譯 `tests/c/blobdump.c`，確認 Python 產生的 blob 與 `include/fw_proto.h` 的結構大小、欄位位移一致，demo 政策在 C 端解出來與 Python 端完全相同。
- **validator**：14 個不合法政策各自觸發預期代碼；合法政策沒有 blocking finding；遮蔽偵測。
- **compiler**：canonical 形式與語意 hash 不受 owner / reason / 順序以外的雜訊影響；baseline 永遠在業務規則前面。
- **交易狀態機**（FakeKernel）：apply → pending → confirm；probe 失敗 rollback；deadline rollback；有 pending 時拒絕；generation 衝突；開機時 pending 被標為 rolled_back。
- **agent**：SO_PEERCRED 權限（myfw / myfw-read / 其他）、未知操作與參數被拒。

## 核心 e2e（`test/e2e.sh`）

QEMU initramfs VM（不碰主機網路），三個 namespace：client / router（載入 myfw）/ server。

| 段落 | 內容 |
|---|---|
| 0–2 | 拓樸基準；載入；非 root 無法查詢或修改 |
| 3–8 | 預設放行；黑名單；first-match 與 `--head/--after`；白名單 + 有狀態回應；本機送出流量；UDP 逾時；新 DROP 規則切斷既有連線 |
| 9–11 | save / load；互動模式；輸入驗證 |
| 11b | 平行流量中 300 次 commit 替換政策：資料完整、核心無錯誤 |
| 12、12b | SNAT（伺服器看到 NAT 位址與 pool port；8 MB 逐 byte 驗證）；SNAT 流量中 commit |
| 13 | DNAT（TCP/UDP；內部主機看到真實外部位址；8 MB 驗證） |
| 13b | 交易：generation、staging、截斷 / 亂碼 blob、中斷 staging 被釋放、兩個寫入者只有一個成功、`--validate-only` |
| 13c | fail closed：flow 表滿、flow 配置失敗、單一 port 的 SNAT pool 用完，都 DROP 並記錄原因 |
| 13d | zone 反偽造、IPv6 在受管理介面上被丟棄 |
| 14–16 | status；卸載 / 重新載入；dmesg 沒有 BUG / WARNING / Oops / lockdep |

這次執行中修正了一個不穩定的測試：「flow 配置失敗」原本只讓**下一次**配置失敗，在 6.17 上被前一段測試遲到的重傳封包先用掉，導致誤判。改成在測試期間讓所有配置都失敗，測完再關掉。

## VM 整合測試（`test/integration`）

在用 Ansible 完整部署（systemd 單元、agent、guard、collector、lab namespace）的 VM 裡執行，測的是「真的照 runbook 操作會發生什麼」。

| 檔案 | 測試 | 驗證什麼 |
|---|---|---|
| `test_matrix.py` | `test_access_matrix` | 10 條路徑的允許 / 拒絕，允許路徑由伺服器端看到的來源位址證明 NAT |
| | `test_dnat_large_transfer_content` | 經 DNAT 下載 20 MB，內容逐 byte 相符 |
| | `test_spoofed_sources_are_dropped_before_the_flow_lookup` | 偽造來源（含冒用既有 flow 的 tuple）在查 flow 之前被丟 |
| | `test_nothing_leaves_untranslated` | 外部主機的 nftables 計數器：來源是內部網段的封包數為 0 |
| | `test_fragments_unsupported_protocols_and_truncated_headers` | 分片、不支援協定、截斷 header 都丟並記錄原因 |
| | `test_ipv6_on_a_managed_interface_is_dropped` | IPv6 不會成為繞過路徑 |
| | `test_management_is_isolated_from_data_zones` | 資料區域連不到管理網與管理服務 |
| | `test_counters_have_one_final_verdict_per_packet` | accept + drop 增量 = 實際封包數 |
| | `test_no_op_reapply_keeps_flows` | 語意相同重新套用不 commit、不重置連線 |
| `test_changes.py` | `test_invalid_candidates_never_touch_the_active_policy` | 不合法政策、亂碼與截斷 blob：generation 與 hash 不變 |
| | `test_interrupted_staging_is_released` | 寫到一半中斷，staging 被釋放 |
| | `test_two_writers_one_generation` | 同一 generation 兩個寫入者只有一個成功，另一個 `ESTALE` |
| | `test_concurrent_fwctl_applies` | 兩個 `fwctl apply` 同時執行只有一個成功 |
| | `test_commits_under_load_never_mix_policies` | 持續流量中 20 次 commit：沒有錯誤服務的回應、沒有未轉換封包 |
| | `test_flow_reset_is_reported_and_new_connections_work` | commit 回報 `flows_reset`；進行中的 SNAT 下載被切斷，新連線正常 |
| | `test_failed_required_service_rolls_back_immediately` | 探測失敗立即 rollback，exit 4 |
| | `test_unconfirmed_change_is_rolled_back_by_the_guard` | 不確認，guard 在 deadline 後 5 秒內 rollback |
| | `test_agent_crash_does_not_stop_the_data_plane_or_the_guard` | kill -9 agent：資料面照常、guard 仍 rollback、agent 被重啟 |
| | `test_guard_is_restarted_and_apply_refuses_without_it` | guard 停止時拒絕 apply；被殺後自動重啟 |
| | `test_capacity_flow_limit_fails_closed` | flow 表滿 → `flow_table_full`，無外洩 |
| | `test_snat_pool_exhaustion_fails_closed` | 2-port pool：第三條連線被拒、計數增加、無外洩 |
| `test_observe.py` | `test_metrics_are_meaningful` | generation、判決、zone、guard、drop 原因指標存在且正確 |
| | `test_collection_failure_is_not_reported_as_zero_traffic` | agent 停止 → `myfw_collector_up 0`，流量序列消失而不是變 0 |
| | `test_event_gap_is_recorded` | 洪泛 1500 個事件 → gap 紀錄、遺失計數 |
| | `test_diagnose_tells_three_faults_apart` | 路由壞、服務停、政策 DROP 三種故障的結論各自正確 |
| | `test_kernel_log_is_clean` | dmesg 沒有 BUG / WARNING / Oops / lockdep |

量測值（VM 內 `/var/lib/myfw-tests/`）：

| 量測 | 值 |
|---|---|
| 持續流量下 20 次 commit 的 gate 時間 | 中位數 0.55 ms、最大 5.0 ms（較早一輪：中位數 1.9 ms、最大 7.7 ms） |
| 持續流量下的請求結果 | 成功 19、失敗 6（進行中的連線被 commit 重置，設計如此）、來自錯誤服務 0 |
| 未確認變更：deadline 後多久完成 rollback（deadline 10 秒） | 1.2 秒（較早一輪 3.7 秒；測試門檻 5 秒） |
| 20 MB DNAT 傳輸 | 內容逐 byte 相符 |
| 外部主機收到的未轉換內部位址封包 | 0 |

## 測試過程發現並修正的問題

| 問題 | 怎麼發現 | 修正 |
|---|---|---|
| lab HTTPS 服務在 accept 迴圈裡做 TLS handshake，一個 NAT session 被重置的 client 會卡住整個服務 | `test_flow_reset_is_reported_and_new_connections_work` 之後所有 wan 探測失敗 | handshake 移到每條連線自己的 thread，並設逾時 |
| 有別人的 pending 變更時，套用一份語意相同的政策會回傳 ok（no-op） | `test_concurrent_fwctl_applies` | 先檢查 pending 再判斷 no-op |
| `fwctl apply --json` 在自動 rollback 後 exit 0 | `test_failed_required_service_rolls_back_immediately` | rollback 時 exit 4 |
| Ansible 更新程式碼後沒有重啟常駐程式 | 部署新版後行為沒變 | 新增 restart handler（保留 namespace 與介面） |
| `control/pyproject.toml` 的 readme 指到套件外，`pip install` 失敗 | CI 前在乾淨 venv 安裝 | 套件自己的 README |
| agent 單元測試在非 root 使用者下失敗（角色取自 /etc/group） | 第一次 CI | fixture 明確給予角色；以 root 與 nobody 各跑一次確認 |
| e2e「flow 配置失敗」測試不穩定 | 6.17 重跑時偶發失敗 | 見上 |
| 效能腳本中途失敗時沒有恢復受管理狀態 | nftables 規則語法錯誤讓腳本中斷，模組停在卸載狀態 | `trap` 一律恢復 |

## 沒有測到的部分

- 只在 TCG 模擬環境測過；沒有在實體網卡、多佇列、KVM 上測。
- 沒有 lockdep / KASAN 的 debug kernel 執行（dmesg 只檢查一般 kernel 會印出的錯誤）。
- 沒有長時間（數天）穩定性測試。
