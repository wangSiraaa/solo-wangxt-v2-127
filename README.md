# 企业邮件档案（Enterprise Mail Archive）

把 EML 文件解析为**可检索的邮件事实**：信头、结构、关系入 PostgreSQL；
附件字节保存在受控本地目录；不做前端，只提供 JSON API。

## 安全与解析约束（设计要点）

| 主题 | 做法 |
| --- | --- |
| 多层 MIME | 递归 `email` 标准库解析，保留真实结构树（part_path 如 `1.1.2`） |
| 字符集 | 按声明解码，UTF-8/GB18030/Big5/Shift_JIS 多档回退，绝不静默丢正文 |
| 内嵌资源 | `inline` + Content-ID 单独分类；HTML 中只允许 `cid:`，远程资源全部剥离 |
| 附件名 | RFC2231 `filename*` 优先；展示名无害化；**存储路径只由 SHA-256 决定** |
| 路径越界 | 受控根目录 realpath 校验 + 符号链接拦截 + 绝对路径/`..` 拒绝 |
| HTML | 标签/属性白名单，script/style/iframe/object 等整段移除；另存一份全转义版；不执行脚本、不加载远程资源；下载强制 `attachment` |
| 会话 | 只依赖 Message-ID/In-Reply-To/References；**主题相同只是弱候选**，不参与合并 |
| 冲突 | 重复 Message-ID 不唯一约束、不合并：两条记录都保留并标记 `retained-conflict`；缺失 ID 正常入库 |
| 循环引用 | 迭代式并查集 + 环检测，5000 节点环也不死循环；环与悬挂引用都保留标记 |
| 损坏边界 | 标准库 defects 全量保留并定位到 part_path；致命错误隔离到 `quarantine/` |
| 日志 | 全局过滤器抹除疑似 base64/QP 长载荷，**附件内容永远不进普通日志** |
| 原 EML 关联 | 原始字节按 SHA-256 存 `raw/`，邮件记录保存 `raw_sha256`/`raw_path`，可一键下载核对 |

## 目录结构

```
app/
  main.py              FastAPI 路由
  service.py           摄取编排（解析→落盘→入库→会话）
  config.py            环境变量配置
  logging_config.py    日志脱敏过滤器
  schemas.py           Pydantic 响应模型
  parsing/
    eml_parser.py      EML -> ParsedMessage（纯函数，无 I/O）
    headers.py         编码词/地址/Message-ID/日期
    sanitizer.py       HTML 白名单清洗（仅标准库 html.parser）
    threads.py         并查集会话图 + 环检测 + 主题弱键
  storage/
    filestore.py       受控目录、内容寻址、越界防护
    archive.py         存储抽象 + 内存实现（离线/CI 后端）
    postgres.py        PostgreSQL 实现
    schema.sql         建表 DDL
samples/               多编码/循环/损坏边界/坏 base64/缺 ID/重复 ID/非 EML 等样例
tests/                 78 个测试（含 PostgreSQL 集成测试）
```

## 快速开始

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 1) 不配置 DSN：使用内存元数据后端（重启丢失，适合本地验证）
MAIL_ARCHIVE_HOME=./data uvicorn app.main:app --port 8000

# 2) PostgreSQL 后端
MAIL_ARCHIVE_DSN="postgresql://user:pass@db:5432/mailarchive" \
MAIL_ARCHIVE_HOME=/var/lib/mail-archive \
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

首次启动自动执行 `app/storage/schema.sql`（需要 `citext` 扩展权限）。

### 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `MAIL_ARCHIVE_HOME` | `/workspace/data` | 受控存储根（attachments/raw/quarantine 自动创建） |
| `MAIL_ARCHIVE_DSN` | 空 | 留空走内存后端；设置后走 PostgreSQL |
| `MAIL_ARCHIVE_MAX_BYTES` | `52428800` | 单次上传上限，0 为不限 |
| `MAIL_ARCHIVE_REBUILD_THREADS` | `true` | 每次摄取后立即重建会话图 |

## API

| 方法 路径 | 说明 |
| --- | --- |
| `POST /api/v1/emails` | multipart 上传 EML（字段名 `eml`） |
| `GET  /api/v1/emails?q=&message_id=&limit=&offset=` | 列表/检索（PG 端走 GIN 全文索引） |
| `GET  /api/v1/emails/{id}` | 邮件事实详情：信头/结构树/正文/附件/缺陷/引用边 |
| `GET  /api/v1/emails/{id}/raw` | 下载原 EML（强制 attachment） |
| `GET  /api/v1/attachments/{id}` | 附件元数据 |
| `GET  /api/v1/attachments/{id}/raw` | 下载附件（受控目录校验，强制 attachment） |
| `POST /api/v1/threads/rebuild` | 重建会话图，返回环/悬挂/弱候选 |
| `GET  /api/v1/threads/{id}` | 会话详情 |
| `GET  /api/v1/conflicts` | 重复/缺失 Message-ID 冲突清单 |
| `GET  /api/v1/failures` · `/api/v1/failures/{id}` | 解析失败列表与定位 |
| `GET  /healthz` | 健康检查 |

### 示例

```bash
curl -F "eml=@samples/01_multi_encoding.eml" http://localhost:8000/api/v1/emails
curl -X POST http://localhost:8000/api/v1/threads/rebuild
curl "http://localhost:8000/api/v1/emails?q=%E5%AD%A3%E5%BA%A6%E6%8A%A5%E5%91%8A"
```

## 摄取返回状态

* `ingested`：正常入库
* `conflict-retained`：Message-ID 与已有邮件相同但内容不同，已保留两条并返回 `duplicate_of`
* `duplicate-content`：SHA-256 完全一致，直接复用既有记录
* HTTP 422 `failed`：致命解析错误，原文件进 `quarantine/`，响应含 `failure_id` 可定位

## 样例

```bash
python samples/generate_samples.py    # 生成多编码/多层/内嵌/危险名样例 01
# 其余 02~08 已随仓库提供
```

## 测试

```bash
pip install pytest httpx embedded-postgres
pytest                          # 内存后端单元/端到端
MAIL_TEST_DSN="postgresql://..." pytest tests/test_postgres.py
```

未配置 `MAIL_TEST_DSN` 时，PG 测试尝试用 `embedded-postgres` 自动拉起本地实例，
两者都不可用则自动跳过。

## 未做 / 明确边界

* 不做任何前端渲染页面；HTML 只存储（清洗版 + 全转义版），由下游消费方决定展示。
* 附件不做病毒查杀、不做 OCR；不跟踪 multipart/partial 分片重组。
* 不做用户认证（企业内网/网关后部署），如需鉴权应在反向代理层补齐。
