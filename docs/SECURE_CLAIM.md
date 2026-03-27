# SinguHunt Secure Claim 部署指南

這份文件說明如何把「trusted assembly context -> ticket server -> on-chain verify」這條路徑真正部署起來。

## 目標

玩家在 EVE 內從 mini gate 打開 dApp 時：

1. dApp 送 `POST /claim-ticket`
2. proxy/edge 代表該 gate 注入受保護的 `x-ef-assembly-id` 與 `x-ef-tenant`
3. `claim-ticket-server` 用 `CLAIM_TICKET_PRIVATE_KEY` 簽短效 ticket
4. dApp 立刻呼叫 `collect_ball(...)`
5. 合約驗 ticket signer、assembly、過期時間、replay

## 重要前提

`x-ef-assembly-id` 不能來自玩家自己可改的 query string 或 request body。

安全來源只能是以下二選一：

1. 上游平台或你控制的 ingress 直接提供受保護的 gate context
2. 每個 gate 各自有固定 proxy URL，proxy 依路徑硬編碼 assembly id

如果你只是把 `?itemId=` 轉成 `x-ef-assembly-id`，那不算 trusted header，玩家仍可偽造。

## 你要先準備的東西

### 1. 後端 signer 私鑰

在根目錄 `.env` 設定：

```bash
CLAIM_TICKET_PRIVATE_KEY=suiprivkey1...
CLAIM_TICKET_PORT=8787
CLAIM_TICKET_HOST=127.0.0.1
CLAIM_TICKET_TTL_MS=30000
TRUSTED_TENANT=utopia
```

### 2. 查 signer address

```bash
pnpm print-ticket-signer-address
```

輸出會是一個 Sui address，例如：

```text
0x8d2c81bce43d5c7c34ea9f6319a08d6ec69d4a45d3311616f3d2c5351a87d967
```

### 3. 寫入鏈上 trusted signer

```bash
pnpm set-ticket-signer -- --address 0x你的_signer_address
```

### 4. 啟動 ticket server

```bash
pnpm claim-ticket-server
```

如果要用 pm2 / systemd / Docker，核心執行命令一樣是：

```bash
node --import tsx ts-scripts/claim-ticket-server.ts
```

### 5. dApp 設定 API 位址

在 dApp 的環境變數中加入：

```bash
VITE_TICKET_API_URL=https://你的-proxy-domain
VITE_SINGUHUNT_PACKAGE_ID=0x...
VITE_GAME_STATE_ID=0x...
VITE_SUI_RPC_URL=https://fullnode.testnet.sui.io:443
```

dApp build 後會直接對 `VITE_TICKET_API_URL/claim-ticket` 發請求。

## Proxy / Edge 範例

以下有兩種安全模式：

1. `單 gate 單 URL`
最簡單。每個 mini gate 綁自己的固定 URL，proxy 直接硬編碼 assembly id。

2. `同一後端，多 gate`
只有在上游已經能提供不可偽造的 gate context 時才安全。

---

## A. Nginx 範例

### A1. 單 gate 單 URL，最穩

假設這個 URL 只服務某一個 gate：

`https://claim.example.com/gates/seven-henna/claim-ticket`

Nginx：

```nginx
server {
    listen 443 ssl http2;
    server_name claim.example.com;

    location = /gates/seven-henna/claim-ticket {
        proxy_pass http://127.0.0.1:8787/claim-ticket;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header x-ef-tenant utopia;
        proxy_set_header x-ef-assembly-id 0xf27500312bd59533d7f99fd575efb0b798d81437066ae79212d880501cadacdd;
    }

    location = /health {
        proxy_pass http://127.0.0.1:8787/health;
    }
}
```

做法：

1. 每個 gate 建一條固定 path
2. 每條 path 都寫死自己的 `x-ef-assembly-id`
3. mini gate 一開始就綁到自己的專屬 path

這種做法最不容易出錯。

### A2. 多 gate 共用後端，但上游已有受保護 header

如果你的上游已經會送出可信的 `X-Upstream-Eve-Assembly-Id`：

```nginx
map $http_x_upstream_eve_assembly_id $trusted_assembly_id {
    default $http_x_upstream_eve_assembly_id;
}

server {
    listen 443 ssl http2;
    server_name claim.example.com;

    location = /claim-ticket {
        proxy_pass http://127.0.0.1:8787/claim-ticket;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;

        # 先覆蓋，不信任客戶端自己送的同名 header
        proxy_set_header x-ef-assembly-id $trusted_assembly_id;
        proxy_set_header x-ef-tenant utopia;
    }
}
```

注意：

1. 不要直接信任瀏覽器送的 `x-ef-assembly-id`
2. 只信任你能控制來源的上游 header

---

## B. Cloudflare Worker 正式方案

正式可部署版本已放進 repo：

- [package.json](/Users/k66/Desktop/singuhunt/cloudflare-proxy/package.json)
- [wrangler.toml.example](/Users/k66/Desktop/singuhunt/cloudflare-proxy/wrangler.toml.example)
- [index.ts](/Users/k66/Desktop/singuhunt/cloudflare-proxy/src/index.ts)

這個 Worker 不是只代理 `/claim-ticket`，而是代理整個 dApp 網域：

- `/gates/<slug>?v=2` 轉發到 Vercel dApp
- `/api/gates/<slug>/claim-ticket` 轉發到 Vercel API

關鍵安全行為：

1. 先清掉所有外部傳入的 `x-ef-*`
2. 只在 `/api/gates/<slug>/claim-ticket` 這條路徑上重建：
   - `x-ef-assembly-id`
   - `x-ef-tenant`
   - `x-ef-context-ts`
   - `x-ef-context-sig`
3. `x-ef-context-sig` 使用 `EF_CONTEXT_SHARED_SECRET` 做 HMAC-SHA256

部署步驟：

```bash
cd cloudflare-proxy
cp wrangler.toml.example wrangler.toml
npm install
npx wrangler secret put EF_CONTEXT_SHARED_SECRET
npx wrangler deploy
```

本地驗證：

```bash
cd cloudflare-proxy
npm run smoke
```

這支 smoke script 不會打外網，它會直接在本機驗證 Worker 的關鍵安全行為：

1. `/api/gates/<slug>/claim-ticket` 會覆蓋外部偽造的 `x-ef-*`
2. `/api/gates/<slug>/deliver-ticket` 也會注入同一組 trusted context
3. `gate slug` 不存在時會回 `404`
4. 一般 page route 不會誤注入 claim headers

mini gate URL 應綁到 Worker 網域：

```text
https://hunt.example.com/gates/singu-01?v=2
https://hunt.example.com/gates/singu-02?v=2
```

---

## C. Vercel Edge / Route Handler 範例

適合你本來 dApp 就在 Vercel。

### `app/api/gates/[gate]/claim-ticket/route.ts`

```ts
import { NextRequest } from "next/server";

const ROUTES: Record<string, { assemblyId: string; tenant: string }> = {
  "seven-henna": {
    assemblyId: "0xf27500312bd59533d7f99fd575efb0b798d81437066ae79212d880501cadacdd",
    tenant: "utopia",
  },
};

export const runtime = "edge";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ gate: string }> },
) {
  const { gate } = await params;
  const route = ROUTES[gate];
  if (!route) {
    return new Response(JSON.stringify({ error: "Unknown gate" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }

  const headers = new Headers(req.headers);
  headers.set("x-ef-assembly-id", route.assemblyId);
  headers.set("x-ef-tenant", route.tenant);

  return fetch("https://backend.example.com/claim-ticket", {
    method: "POST",
    headers,
    body: req.body,
  });
}
```

mini gate URL：

```text
https://your-dapp.vercel.app/api/gates/seven-henna/claim-ticket
```

## 推薦落地方式

如果你現在要正式上線，直接用 repo 內這個 Cloudflare Worker 方案即可。它比等待平台原生 protected header 更快落地，而且已和目前的 Vercel `/api/gates/<slug>` 路徑對齊。

## 部署後 Smoke Test

下面這份清單照順序跑。

### A. 後端與 signer

1. `pnpm print-ticket-signer-address`
   確認 address 有輸出。
2. `pnpm set-ticket-signer -- --address 0x...`
   確認交易成功。
3. 啟動 `pnpm claim-ticket-server`
   確認 log 有 `Trusted signer: 0x...`
4. 打 proxy 的 `/health`
   確認回傳 `ok: true`

### B. 單 gate ticket 驗證

1. 在 EVE 內走到目標 mini gate
2. 打開 dApp
3. 確認畫面顯示目前 assembly id
4. 按 `CLAIM SINGU HERE`
5. 確認 network 面板中 `POST /claim-ticket` 成功
6. 確認 response 裡的 `assemblyId` 正是這個 gate 的 object id
7. 確認錢包彈出交易簽署
8. 確認交易 digest 成功出現在 UI

### C. 鏈上狀態驗證

1. 執行 `pnpm query-hunt`
2. 確認對應 `ball_index` 已變成 collected
3. 確認 collector 是剛剛的玩家地址
4. 確認玩家錢包出現新的 `DragonBall` 物件

### D. 作弊驗證

1. 在不是目標 gate 的地方直接打開 dApp URL
2. 按 claim
3. 預期：
   ticket API 不會給該 gate 的合法 ticket
   或鏈上因 `E_ASSEMBLY_MISMATCH` / `E_INVALID_TICKET` 失敗

4. 複製舊 ticket 重送一次
5. 預期鏈上因 `E_TICKET_REPLAY` 失敗

6. 等 ticket 超過 TTL 再送
7. 預期鏈上因 `E_TICKET_EXPIRED` 失敗

### E. 多 gate 驗證

1. 再配置第二個 gate 專屬 path
2. 在第二個 gate 打開 dApp
3. 確認 `/claim-ticket` 回來的是第二個 gate 的 `assemblyId`
4. 確認只能 claim 第二個 gate 對應的球

## 最常見錯誤

### 問題 1：票據 API 成功，但鏈上 `E_INVALID_TICKET`

檢查：

1. `set_ticket_signer` 寫進鏈上的地址是否和 `pnpm print-ticket-signer-address` 一樣
2. proxy 注入的 `x-ef-assembly-id` 是否和合約內該 gate 的 object id 一樣
3. ticket TTL 是否太短

### 問題 2：玩家可手改 `?itemId=` 成功 claim

代表你把 query string 當 trusted source 了。要改成：

1. proxy path 寫死 assembly id
2. 或只吃平台保護 header

### 問題 3：dApp 按 claim 沒跳錢包

檢查：

1. 是否真的在 EVE Vault / EVE Frontier Client Wallet 環境內
2. `EveFrontierProvider` 是否有包住 React app
3. `VITE_SINGUHUNT_PACKAGE_ID` / `VITE_GAME_STATE_ID` 是否正確

## 建議你現在的做法

先不要追求最泛化。

先用這個順序：

1. 選 1 個 gate
2. 給它 1 條固定 proxy URL
3. Nginx 或 Cloudflare Worker 把 assembly id 寫死
4. 跑完 smoke test
5. 成功後再擴成 7 個 gate

這樣最快能把安全 claim 真的跑起來。
