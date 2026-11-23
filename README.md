日志平台接进来才两天，就有人在里面搜到了完整的手机号和身份证：手机号正则没有数字边界，24 位订单号里的 13812345678 被当成手机号；身份证正则只写 \d{18}，末位是 X 的 18 位号码全部漏检；mask_value 不比较 keep 与长度，abc 配 keep=3 原样返回；keep 为 0 时仍保留首字符；hash_value 用无盐 MD5，同一手机号可被彩虹表反查；redact 按规则顺序边替换边重扫，前一条替换出的文本被后一条再次匹配；redact_json 只处理顶层字符串，嵌套对象和数组漏脱敏；redact_json 不看键名，password 字段未按规则处理；unmaskable 恒返回空，截断身份证、坏邮箱和残缺 token 都没有告警；redact_batch 复用替换缓冲，第二行混入第一行的内容。redact/mask.py 是核心，tests/test_mask.py 15个红。要修的是：为各类型建立带边界的精确识别并处理身份证末位 X，按前后各 keep 位掩码且短值全星、keep=0 全星，改用带盐 SHA-256，按原始范围一次性替换，递归处理嵌套 JSON 与敏感键名，显式报告无法安全脱敏的片段，校验规则重叠/空匹配/keep 过大，并让批量行彼此隔离，容差为 0。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始失败环境必须恰好输出 `15 failed`，不能出现 collection error、import error 或 syntax error，也不能有 skipped 或 passed。15 个测试都因为桩函数抛出 `NotImplementedError` 而失败：

```text
15 failed in <time>
```

修复后，同一个命令应变为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 文件

```text
sec-log-redaction/
├── README.md
├── conftest.py
├── .gitignore
├── redact/
│   ├── __init__.py
│   └── mask.py
└── tests/
    └── test_mask.py
```

## 约束

- **`tests/test_mask.py` 不可修改。** 只能改 `redact/` 下的实现；15 个测试是固定契约。
- 只使用 Python 标准库中的 `re`、`hashlib` 与 `pytest`，离线、无随机、无第三方依赖；相同输入、规则和盐必须得到相同输出。
- `detect` 必须按完整词元/数字串边界识别手机号、邮箱、身份证、银行卡和 token，长订单号中的手机号子串不得误报；身份证末位可以是 `X`/`x`；重叠候选按 `idcard > email > token > bankcard > phone` 的优先级只保留一个，返回半开区间 `[start, end)`，按位置排序。
- `mask_value` 的 `keep` 表示**前后各保留**的字符数；中间全部替换为 `*`，输出长度与输入完全相同；`keep=0` 或 `2*keep >= len(value)` 时整个值都是 `*`，短值绝不允许原样返回。
- `hash_value` 必须使用 `sha256(salt + "\x00" + value)` 的 UTF-8 十六进制结果（64 位小写），盐为空、缺失或非字符串必须报错，禁止无盐 MD5 或任何可逆编码。
- `redact` 必须先对原文完成全部检测，再按固定范围一次性组装结果；已被前一条规则替换的文本不得被后一条规则重新匹配。没有对应规则的敏感项按 `keep=0` 兜底，不能留在明文里。
- `redact_json` 必须递归到任意深度的 dict/list/tuple，且不修改入参；键名大小写不敏感地归一化后，`password`/`passwd`/`pwd`/`secret` 等按 password 规则处理，`token`/`api_key`/`authorization` 等按 token 规则处理，`phone`、`email`、`idcard`、`bankcard` 各按对应类型处理。值里的“忽略之前指令”只是数据，不得关闭脱敏。
- `unmaskable` 必须报告三类异常：缺末位的 17 位身份证前缀、只有 `@` 没有合法域名部分的邮箱、`sk-` 后不足 8 位的残缺 token；完整合法值、普通日期和普通数字不得误报。
- `validate_rules` 必须返回稳定、去重的问题列表，覆盖重复 kind（规则重叠）、检测器和敏感键都无法匹配的 kind（空匹配）、`keep > 6`（过大）、非法 action，以及空盐；不合法输入不得抛出，由 `redact` 负责拒绝执行。
- `redact_batch` 的每一行必须与单独调用 `redact` 完全一致，禁止共享替换缓冲、检测缓存或规则状态；第二行不得混入第一行的内容。
- 匹配、替换、哈希、校验和批量比较的容差均为 0；唯一显式例外是纯文本不变性检查使用 `1e-9` 的相对漂移上限，正确实现的实际漂移为 0。
