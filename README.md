[English](README_EN.md) | 简体中文

# IDA NO MCP

**告别 IDA MCP 复杂、冗长、卡顿的交互模式。**  

**AI 逆向，无需额外配置。**  

Simple · Fast · Intelligent · Low Cost

## 核心理念

Text、Source Code、Shell 是 LLM 原生语言。

AI 飞速发展，没有固定模式，工具应该保持简单。

把 IDA 反编译结果导出为源码文件，直接丢进任意 AI IDE（Cursor / Claude Code / ...），天然适配索引、并行、切片（反编译超大函数）等优化。

## 使用

### 1. GUI 模式 (交互式)

- **方法 A**：复制 `INP.py` 全部内容 → 粘贴到 IDA Python 窗口 → 回车。
- **方法 B**：在 IDA 中选择 `File` -> `Script file...` -> 选择 `INP.py`。

默认导出目录：`{IDB所在目录}/export-for-ai/`

### 2. Headless 模式 (命令行)

适用于批量处理或自动化流程：

```bash
/path/to/idat -c -A -S"INP.py [export_dir]" <target_file>
```

*注：如果未指定 `export_dir`，则默认导出到 `{IDB所在目录}/export-for-ai/`。*

## 导出内容

| 文件/目录 | 内容 |
|-----------|------|
| `decompile/` | 反编译 C 代码（含调用关系） |
| `strings.txt` | 字符串表 |
| `imports.txt` | 导入表 |
| `exports.txt` | 导出表 |
| `memory/` | 内存 hexdump（1MB 分片） |

## Tips

在 IDB 目录下可以同时添加更多上下文，让 AI 获得完整视角：

| 目录 | 内容 |
|------|------|
| `apk/` | APK 反编译目录（APKLab 一键导出） |
| `docs/` | 逆向分析报告、笔记 |
| `codes/` | exp、Frida scripts、decryptor 等脚本 |

最先进的 AI 模型能够利用所有信息与脚本，为你提供最强力的逆向工程辅助。
