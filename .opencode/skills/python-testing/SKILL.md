---
name: "python-testing"
description: ">"
---

# Python Testing

*Sourced from killvxk-malskills-zh*

# Python 测试

编写**确定性**、**可读性强**、**易维护**测试的高效指导。

## 激活时机

- 为新增或现有代码添加测试（单元/集成）
- 重构测试以降低不稳定性
- 设计 fixture 和测试组织结构
- 添加覆盖率、CI 检查或异步测试

---

## 核心规则

- 优先使用**小型单元测试**覆盖业务逻辑；使用集成测试覆盖边界。
- 使用 pytest fixture 消除重复，但避免 fixture 过度工程化。
- 避免在测试中使用 sleep；通过条件/事件进行同步。
- 在边界处（网络、时间、数据库）使用 mock，而非滥用 mock。
- 覆盖率是信号：目标是有意义的断言，而非单纯追求行覆盖率。

---

## 资源

按需加载：

- `references/tdd-and-structure.md` —— TDD 循环、命名规范、测试组织
- `references/fixtures-parametrize.md` —— fixture（作用域、autouse）、参数化模式
- `references/mocking.md` —— unittest.mock、正确的 patch 方式、async mock
- `references/async.md` —— pytest-asyncio 模式与常见陷阱
- `references/coverage-ci.md` —— pytest-cov、覆盖率规范、CI 技巧
- `references/commands.md` —— 常用 pytest 命令与选择器

