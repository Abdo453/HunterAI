---
name: "c-testing"
description: ">"
---

# C Testing

*Sourced from killvxk-malskills-zh*

# C Testing

可靠 C 测试与 bug 发现的实用工作流程。

## 适用场景

- 为 C 函数添加单元测试
- 围绕模块构建小型测试驱动
- 调试失败的测试或内存损坏问题
- 启用 sanitizer 或模糊测试以复现崩溃

---

## 核心规则

- 保持单元测试的确定性和隔离性。
- 单元测试中避免真实的网络调用和时间依赖。
- 在 CI 中运行 ASan/UBSan，以获取内存问题和未定义行为 (UB) 的信号。

---

## 资源

按需加载：

- `references/harness.md` — 测试驱动结构、断言、Unity/cmocka 选项
- `references/cmake-ctest.md` — CMake/CTest 模式、标签、sanitizer 预设、MinGW 交叉编译
- `references/sanitizers-fuzzing.md` — ASan/UBSan 用法及最简模糊测试目标示例
- `references/debugging.md` — gdb/lldb、Valgrind、MinGW objdump/nm、MSVC dumpbin/WinDbg、ASan 环境变量

