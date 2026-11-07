# 9 分鐘展示腳本

情境：「內部使用者要用 DMZ 的 HTTPS 服務；外部測試者只能透過公開的 port 連到同一個服務；其他一律關閉。要能說出哪些路徑是開的、什麼時候改的、出事怎麼復原。」

事前準備：VM 已依 [runbook](runbook.md) 部署，`fwctl status` 顯示 demo 政策已確認。以下指令都在防火牆主機上執行（`labadmin` 帳號，屬於 `myfw` 群組）。

## 0:00–1:00 拓樸與存取矩陣

```bash
cat lab/inventory.yaml | sed -n '/zones:/,/endpoints:/p'
fwctl verify
```

說明重點：三個區域、各自一張網卡；10 個探測是從各端點的 namespace **實際連線**，允許的路徑會顯示伺服器看到的來源位址。

## 1:00–2:00 政策即程式碼

```bash
sed -n '/rules:/,$p' policies/demo.yaml
fwctl validate policies/demo.yaml
fwctl validate policies/invalid/opens-mgmt-service.yaml   # danger：開放管理服務
fwctl validate policies/invalid/shadowed.yaml             # 被遮蔽的規則
```

說明重點：每條規則有 owner / reason；檢查分 error / unsupported / danger / warning；改 owner 或註解不會改變語意 hash。

## 2:00–3:30 套用與 NAT 證據

```bash
cp policies/demo.yaml /tmp/new.yaml
sed -i 's/destination_ports: \[443\]$/destination_ports: [443, 4443]/' /tmp/new.yaml   # 兩條內部規則都多開 4443
fwctl diff /tmp/new.yaml
fwctl apply /tmp/new.yaml        # commit + 探測 → pending
fwctl confirm <change-id>
sudo ip netns exec lan curl -s --cacert /var/lib/myfw-lab/pki/ca.pem https://192.0.2.10/     # wan-host 看到 192.0.2.1:2xxxx
sudo ip netns exec wan curl -s --cacert /var/lib/myfw-lab/pki/ca.pem https://192.0.2.1:8443/ # dmz-web 看到 192.0.2.10
sudo uapp conn
```

說明重點：gate 時間、`flows_reset`；SNAT 讓外部主機只看到 gateway 位址，DNAT 讓內部服務看到真實外部位址。

## 3:30–4:30 無效候選不會污染線上設定

```bash
sudo uapp policy show | head -3
head -c 3000 /dev/urandom > /tmp/garbage.bin
sudo uapp policy apply /tmp/garbage.bin --expected-gen current; echo "exit=$?"
sudo uapp policy show | head -3          # generation 與 hash 不變
```

## 4:30–6:00 錯誤政策自動復原

```bash
cp policies/demo.yaml /tmp/broken.yaml
python3 - <<'EOF'
import yaml; d = yaml.safe_load(open('/tmp/broken.yaml'))
d['rules'] = [r for r in d['rules'] if r['id'] != 'lan-dmz-web']   # 誤刪內部存取
yaml.safe_dump(d, open('/tmp/broken.yaml', 'w'), sort_keys=False)
EOF
fwctl apply /tmp/broken.yaml; echo "exit=$?"      # 探測失敗 → 立即 rollback，exit 4
fwctl history --limit 3
```

再示範「沒確認」：`fwctl apply /tmp/new.yaml --confirm-timeout 15`，不要 confirm，15 秒後 `fwctl status` 已回到確認版。

## 6:00–7:00 控制面與資料面分離

```bash
sudo systemctl kill -s KILL myfw-agent
sudo ip netns exec lan curl -s --cacert /var/lib/myfw-lab/pki/ca.pem https://10.10.20.10/   # 照常
sleep 3; fwctl status       # systemd 已重啟 agent，狀態一致
```

## 7:00–8:00 根因分析

```bash
sudo myfw-lab fault route-break dmz-web
fwctl diagnose --from lan-client --to 10.10.20.10 --port 443 --check https   # 政策允許，但目標沒有回程路由
sudo myfw-lab fault route-fix dmz-web

sudo myfw-lab fault service-stop dmz-web
fwctl diagnose --from lan-client --to 10.10.20.10 --port 443 --check https   # 沒有服務在聽
sudo myfw-lab fault service-start dmz-web
```

說明重點：同樣是「連不上」，診斷會分出政策 drop（指出規則）、路由、服務三種原因；證據不足時明說不能判定。

## 8:00–9:00 證據與限制

- [test-report.md](test-report.md)：e2e 134 項（兩個 kernel）、VM 整合測試、重開機測試。
- [performance.md](performance.md)：baseline / nftables / 原版 / v2 對照與測量限制。
- [incidents/](incidents/)：SNAT pool 耗盡、錯誤政策復原。
- 限制：只支援 IPv4、只在 init_net、每次 commit 會重置既有 flow、數字來自 TCG 模擬的 VM，不能外推到實體設備。
