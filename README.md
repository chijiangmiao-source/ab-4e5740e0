# 机载维护镜像 · 离线装载链接审计 (Airborne Maintenance Image Link Audit)

离线装载前，对至多 12 个按命令行顺序排列的 **Base64 ELF64 ET_REL 可重定位对象**
或 **GNU ar 静态归档**做原始字节校验与左至右链接裁决，防止：

- 跨归档循环依赖被遗漏（归档经过顺序导致成员未抽取）；
- 同一外部符号的两个强定义被链接器悄然择一；
- 损坏的归档成员名表 / 符号索引 / 非 x86-64 或压缩成员混入装载镜像。

裁决按稳定审计标识冻结（SQLite），可按标识原样重开；同一标识换用不同输入提交
返回 **409**，冻结结论永不静默改变。

## 裁决语义（与 GNU ld 可观测行为一致）

| 情况 | 裁决 |
|---|---|
| 对象 (`.o`) | 在命令行位置全量纳入：先登记定义，再登记引用 |
| 强定义 + 强定义 | **拒绝**（`duplicate_strong_definition`，定位第二次触发位置） |
| 强 / COMMON / 弱定义同符号 | 强 > COMMON > 弱（经 binutils 验证）；同强度先到先得；取舍全程记录为 `decisions` |
| 弱未定义引用 | 不抽取归档成员、不导致失败，仅在 `weak_unresolved` 报告 |
| 普通归档 (`.a`) | 经过时仅按当前未定义集合依**符号索引顺序**抽取成员；归档内部反复扫描至自身不动点 |
| 成组归档（连续勾选 `--start-group`） | 整组一轮轮反复扫描，直到某轮无任何抽取（未定义集合不再变化） |
| 链接结束仍有强未定义 | **拒绝**（`undefined_at_close`），报告最终未定义集合与全部引用位置 |
| 损坏 ar 索引 / 成员不是合法 ELF / 压缩成员 / 非小端 x86-64 | **拒绝**（`illegal_member`，定位首个触发的命令行位置） |

每次抽取与每轮都产生证据：`extraction_order`（触发符号、成员头偏移、轮次、
范围）与 `rounds`（轮前未定义集合快照、本轮抽取成员）。

## 原始字节校验范围

- ELF：魔数、`ELFCLASS64`、`ELFDATA2LSB`、`ET_REL`、`EM_X86_64`、版本/标志、
  节头表边界、`.symtab`/`.strtab` 链接关系、表项尺寸与空项、外部符号空名、
  `SHN_XINDEX`、`SHF_COMPRESSED`（拒绝压缩节）。
- ar：`!<arch>\n` 魔数（拒绝 `!<thin>`）、60 字节成员头与 `` `\n `` 标记、
  数值字段严格十进制/八进制、奇尺寸成员 LF 填充、成员尺寸越界、`//` 长名表
  （唯一性与偏移边界）、`/` 与 `/SYM64` 符号索引（**大端**序计数/偏移/名称）、
  索引偏移必须指向真实成员头、索引声称的每个符号必须确为该成员定义（否则判为
  损坏索引）、每个成员再做完整 ELF 校验。

## API

- `GET  /health` → `{"status":"ok"}`
- `POST /api/audits` — body：
  ```json
  {
    "audit_id": "ACMAINT-2026.10-0007",
    "items": [
      {"name": "main.o", "content_base64": "...", "grouped": false},
      {"name": "libx.a", "content_base64": "...", "grouped": true}
    ]
  }
  ```
  新建冻结返回 **201**；同标识同输入幂等重提返回 **200**（`reopened:true`）；
  同标识不同输入返回 **409**；请求非法（Base64/数量/标识）返回 **400**。
  业务裁决拒绝（重复强定义、未定义闭合、非法成员等）仍以 **201** 冻结一份
  `status:"rejected"` 结论。
- `GET  /api/audits/{audit_id}` — 重开冻结结论（200 / 404）。
- `GET  /api/audits` — 冻结结论索引。

## 本地开发（无第三方 Python 依赖）

```bash
# 后端（标准库 http.server + sqlite3）
cd backend
python3 -m unittest tests.test_parsers tests.test_linker -v
AUDIT_DB=/tmp/audits.db STATIC_DIR=../frontend/dist PORT=8080 \
  python3 -m app.server

# 前端
cd frontend
npm ci && npm run build      # tsc --noEmit && vite build
npm run dev                  # 开发服务器（/api 与 /health 代理到 8080）
```

## Docker Compose

```bash
docker compose build
docker compose up -d                       # api + web(nginx:8080->80)
# 健康端点：
curl -s http://localhost:8080/health       # 经 web 的 nginx 反代
# 一次性 verify（解析规则测试 → 前端构建 → 活服务 API/HTTP 冒烟），退出码报告：
docker compose up --abort-on-container-exit --exit-code-from verify
```

`verify` 服务在**一次运行**内顺序执行：

1. 49 项解析规则 / 链接语义 unittest（原始字节夹具，不依赖宿主 gcc/ar）；
2. `npm ci` + `tsc --noEmit` + `vite build` 前端构建检查；
3. 对活的 `api`/`web` 做 28 项 HTTP/API 断言：跨归档循环在组外拒绝、组内
   反复扫描至不动点后接受、每轮未定义集合证据、按标识重开、指纹冲突 409、
   重复强定义拒绝、损坏归档索引拒绝、非法 Base64、13 输入上限、404、
   页面与哈希 JS 资源、健康反代、冻结索引。

冒烟标识每次运行唯一（毫秒后缀），因此 verify 可对持久化数据库重复执行而
结果稳定；全绿退出码 `0`，任一失败退出码 `1`。

## 目录

```
backend/app/    elf.py（ELF64 解析） ar.py（GNU ar 解析）
                linker.py（左至右/归档/成组裁决引擎） audit.py（输入与证据）
                storage.py（冻结结论） server.py（HTTP + 静态托管）
backend/tests/  原始字节夹具 + 48 项规则测试
frontend/       Vite + TypeScript 单页（真实 fetch API，无模拟）
verify/         一次性验证编排（run.py）与镜像
docker-compose.yml  api / web / verify 三服务
```
