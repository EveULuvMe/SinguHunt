# Singu Hunt

A blockchain-based scavenger hunt game built on Sui, played inside EVE Frontier's Utopia world.

**Author:** k66

---

## Game Modes

## Daily Schedule (UTC+8)

| Mode | Registration (3 min) | Game Time | Duration |
|------|---------------------|-----------|----------|
| 1. Solo Race | 08:57 - 08:59 | 09:00 - 09:07 | 7 min |
| 2. Team Race | 09:57 - 09:59 | 10:00 - 10:07 | 7 min |
| 3. Deep Decrypt | 10:57 - 10:59 | 11:00 - 11:07 | 7 min |
| 4. Large Arena | 12:57 - 12:59 | 13:00 - 13:12 | 12 min |
| 5. Obstacle Run | 14:27 - 14:29 | 14:30 - 14:42 | 12 min |

Registration opens 3 minutes before game start and closes 1 minute before.

---

### 1. Solo Race (MODE_SOLO_RACE)

Players race to collect all required Singu from mini gates and deliver them to the end gate. The top 5% of registered players (at least 1) earn the "Singularity Vanguard" NFT. Winner slots = max(1, ceil(registered * 5%)).

**Completed:**
- On-chain game loop: start_hunt → collect_ball → deliver_ball → claim_achievement → expire_hunt
- Three-layer anti-cheat: Cloudflare HMAC context signing → Vercel Ed25519 ticket issuance → Sui Move on-chain verification
- Registration system: open_registration → register_for_hunt → start_hunt closes registration
- Top 5% winner slots: WinnerSlotsKey/WinnerCountKey dynamic fields, calculated from RegCountKey at hunt start
- Registration check: claim_achievement requires RegPlayerKey existence
- Per-mode game duration: start_hunt_with_selection accepts game_duration_ms parameter
- Random gate selection from pool (Fisher-Yates shuffle) via start_hunt_with_selection
- Multi-mode auto-scheduler (PM2 daemon): 5 daily sessions with registration windows
- Frontend: HuntBoard with claim/deliver UI, status bar (Session/Mode/Winner/Claimed/Delivered)
- Burn expired DragonBall NFTs (permissionless, clock-based)
- Bulletin board module for announcements
- Gate configuration scripts (configure-gates, set-assembly-url, find-assemblies)
- Deliver-ticket API endpoint for end gate verification
- Character ID registration: register_for_hunt stores CharacterRegKey(epoch, character_id) for turret lookup
- Turret whitelist: Mode 1-4 registered players are whitelisted (not attacked) during active hunt

**TODO:**
- Deploy upgraded contract via upgrade capability
- Frontend: registration UI (register button during registration window)
- Frontend: show winner slots / remaining slots
- Frontend: historical session list / leaderboard
- Resolve EVE Frontier mini gate visibility bug (GitHub issue filed)

---

### 2. Team Race (MODE_TEAM_RACE)

Awaiting k66's gameplay design specification.

**Completed:** Mode constant + registration/scheduling infrastructure.

**TODO:** Pending k66's detailed design.

---

### 3. Deep Decrypt (MODE_DEEP_DECRYPT)

Awaiting k66's gameplay design specification.

**Completed:** Mode constant + registration/scheduling infrastructure.

**TODO:** Pending k66's detailed design.

---

### 4. Large Arena (MODE_LARGE_ARENA)

Awaiting k66's gameplay design specification.

**Completed:** Mode constant + registration/scheduling infrastructure.

**TODO:** Pending k66's detailed design.

---

### 5. Obstacle Run (MODE_OBSTACLE_RUN)

Players must clear Mini Gate checkpoints **in sequential order** (gate 0 → 1 → 2) while turrets **actively attack registered participants**. This is the only mode where turrets target players instead of protecting them.

**Key mechanics:**
- Sequential gate enforcement: contract checks `player_collected_count == shard_index` before allowing claim
- Turret blacklist: registered players are attacked (Mode 1-4 whitelist is reversed)
- Unregistered players are also attacked (same as other modes)

**Flow:** Register → Launch → Gate 0 → Gate 1 → Gate 2 (sequential) → Return to Home → Claim Achievement

**Completed:**
- Mode constant + registration/scheduling infrastructure
- Sequential gate ordering in `collect_singu_shard` (E_INVALID_GATE_ORDER)
- Turret blacklist logic in `singu_turret::get_target_priority_list`
- `CharacterRegKey` dynamic field for turret character_id lookup
- `is_character_registered(game, epoch, character_id)` public view function

**TODO:**
- Deploy upgraded singuhunt contract via upgrade capability
- Deploy singu-turret contract to each turret assembly

---

## In-Game Hardware Inventory

k66 needs to build/deploy the following structures in EVE Frontier Utopia:

### Current Status

| Structure | Needed | Built | Status |
|-----------|--------|-------|--------|
| Network Node | 4+ | 2 | Need 2+ more (each supports max 3 turrets) |
| Mini Gate (Home) | 1 | 1 | Deployed as singu-home (Start/End + Bulletin) |
| Mini Gate (Collect) | 3 | ? | For Mode 1/2/5 — singu-mini-001~003 |
| Heavy Gate | 3 | ? | For Mode 4 — singu-heavy-001~003 |
| SSU | 3 | ? | For Mode 3 — singu-ssu-001~003 |
| Smart Turret | 10 | 0 | Base defense — needs 4+ Network Nodes |

### Turret Deployment Plan

- Each Network Node supports **max 3 Smart Turrets** within **25KM**
- 10 turrets requires at least **4 Network Nodes** (3+3+3+1)
- Currently have 2 Network Nodes → need to build **2 more**
- Turrets must be manufactured via: Mine ore → Refinery → Printer → Assembler → Deploy

### SSU Deployment Rules

- Must be >50KM from any station
- Must be >5KM from other deployables
- Must be >200KM from other SSUs
- Need fuel to activate after deployment

---

## Hardware Deployment — In-Game URLs

Base URL: `https://singuhunt-proxy.k66inthesky.workers.dev`

Singu Hunt Home URL: `https://singuhunt-proxy.k66inthesky.workers.dev/singu-home?v=2`

Landing Page (Production): `https://eveuluv.me/`

Landing Page (Staging): `https://eveuluvme-site.pages.dev/`

Singu Vault URL: `https://dapp-seven-henna.vercel.app/`

### Singu Hunt — Home (Start/End + Bulletin)

| Slug | Assembly ID | In-Game URL |
|------|-------------|-------------|
| `singu-home` | `0xf27500312bd59533d7f99fd575efb0b798d81437066ae79212d880501cadacdd` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-home?v=2` |

### Singu Vault — Exchange SSU

| Name | ROOT | Location | dApp URL |
|------|------|----------|----------|
| Singu Vault - Exchange | `1000000020459` | Next to Singu Hunt Home | `https://dapp-seven-henna.vercel.app/` |

> This is a **standalone SinguVault dApp** (not routed through singuhunt-proxy).
> Future custom domain: `https://vault.eveuluv.me`

### Mini Gate x 3 (Mode 1 Solo Race / Mode 2 Team Race / Mode 5 Obstacle Run)

| Slug | Assembly ID | In-Game URL |
|------|-------------|-------------|
| `singu-mini-001` | `0x4e3eb175c4bac0edf3509b8681bf97d6439fc17bd462422f305f3db07599c36c` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-mini-001?v=2` |
| `singu-mini-002` | `0xe9799223e7a160bb25c41cbd581631ca330ed1e81ef5e799bad962e646f48d45` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-mini-002?v=2` |
| `singu-mini-003` | **待填** | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-mini-003?v=2` |

### SSU x 3 (Mode 3 Deep Decrypt)

| Slug | Assembly ID | In-Game URL |
|------|-------------|-------------|
| `singu-ssu-001` | `0x0703e74e68bea379250206b285904035649dfa2c3a544fb4571967f264a9877e` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-ssu-001?v=2` |
| `singu-ssu-002` | `0xf956e5ca8447056f5bad7044cd60c8c78609ca703a2d4c797bc0e944e5206156` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-ssu-002?v=2` |
| `singu-ssu-003` | `0x1d238ac1faca0d5f6e6efd132f1a3b1dc5e172d68e2547d7da10c85798d247a3` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-ssu-003?v=2` |

### Heavy Gate x 3 (Mode 4 Large Arena)

| Slug | Assembly ID | In-Game URL |
|------|-------------|-------------|
| `singu-heavy-001` | `0x39913c81d0fec7f35cbcd93b5672e24a7a4a737f474c493b5c8f91c4beacc81e` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-heavy-001?v=2` |
| `singu-heavy-002` | `0xffacc0a31c2043738cacd150a7ffbbabf258c2a45aa49df09b1b2d1376eec364` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-heavy-002?v=2` |
| `singu-heavy-003` | `0x1840453d141280f202802c3eb2a525affe572a887125f47e1dbf43dee5786b31` | `https://singuhunt-proxy.k66inthesky.workers.dev/singu-heavy-003?v=2` |

### Deployment Notes
- Page routes use root-level slug: `/singu-xxx-NNN` (e.g. `/singu-mini-001`)
- API routes remain: `/api/gates/[slug]/(claim-ticket|deliver-ticket)`
- Legacy `/gates/[slug]` routes still supported for backward compatibility
- `requiredSinguCount = 3` — each hunt randomly picks 3 from the pool (Fisher-Yates shuffle)
- Pool can grow; code auto-handles any pool size
- SSU spacing must be >200 km in-game
- After deployment, record each Assembly ID and update: `config/gates.json`, `wrangler.toml` (`TRUSTED_GATE_MAP`), `HuntBoard.tsx` (`SLUG_ASSEMBLY_MAP` + `GATE_METADATA`), Vercel env vars
- Network: **Utopia** testnet (`TRUSTED_TENANT = "utopia"`)

---

## Reference Documents

### EVE Frontier

| Document | Description | Link |
|----------|-------------|------|
| World Upgrades | How to handle EVE Frontier world contract upgrades and update package IDs | https://docs.evefrontier.com/tools/world-upgrades |
| World Contracts v0.0.21 Release | Release notes for the Utopia world upgrade that changed WORLD_PACKAGE_ID | https://github.com/evefrontier/world-contracts/releases/tag/v0.0.21 |
| EVE Frontier Docs | Official documentation for building dApps in EVE Frontier | https://docs.evefrontier.com |
| World Contracts Repo | Source code for EVE Frontier's on-chain world contracts | https://github.com/evefrontier/world-contracts |

### Style References

| Document | Description | Link |
|----------|-------------|------|
| eve-frontier-apps README | README 排版參考範本（置中標題、badges、分隔線區段、表格、底部署名） | https://github.com/Econmartin/eve-frontier-apps/blob/main/README.md |
