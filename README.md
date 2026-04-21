# Decrypt-BTC

BTC助记词破解工具 - 基于Rust和OpenCL的GPU加速实现

## 项目状态

✅ **已完成**
- 项目初始化和基础架构
- 配置系统（YAML格式）
- 助记词模块（BIP39单词表加载、候选词生成、校验位验证）
- BTC地址生成（Legacy格式，基于bitcoin 0.30库）
- OpenCL内核文件结构（10个.cl文件）
- GPU搜索器完整实现（动态索引计算、性能统计）
- 命令行参数支持（配置文件、批处理大小、搜索空间限制）
- 完整的测试套件（40个测试用例，100%通过率）
- 开发文档完善

🚧 **进行中**
- GPU内核优化（PBKDF2、secp256k1、SHA256、RIPEMD160）
- 多GPU支持
- 搜索进度显示
- 中断和恢复功能

## 快速开始

### 1. 环境要求

- Rust 1.70+
- OpenCL 1.2+ SDK
- 支持OpenCL的GPU（建议显存≥4GB）

### 2. 编译

```bash
cargo build --release
```

### 3. 配置

编辑 `config/example.yaml`：

```yaml
mnemonic_size: 12
passwords: []
target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs"
word_positions:
  word0: ["abandon", "ability", "able", "about"]
  word1: []  # 空数组表示使用全部2048个词
  # ... word2-word11
```

### 4. 运行

```bash
# 自动检测GPU并执行搜索（默认搜索空间限制：500万）
cargo run --release

# 使用自定义配置
cargo run --release -- --config ./config/example.yaml

# 调整搜索空间限制为1000万
cargo run --release -- --max-search-space 10000000

# 自定义GPU批处理大小
cargo run --release -- --batch-size 50000
```

### 5. 命令行参数

```
Options:
  -c, --config <CONFIG>              配置文件路径 [default: config/example.yaml]
      --batch-size <BATCH_SIZE>      GPU批处理大小 [default: 10000]
      --max-search-space <LIMIT>     最大搜索空间限制 [default: 5000000]
  -h, --help                         显示帮助信息
  -V, --version                      显示版本信息
```

## 项目结构

```
decrypt-btc/
├── config/
│   └── example.yaml          # 配置示例
├── src/
│   ├── main.rs               # 程序入口 ✅
│   ├── lib.rs                # 库模块 ✅
│   ├── config.rs             # 配置解析与验证 ✅
│   ├── mnemonic.rs           # 助记词处理 ✅
│   ├── address.rs            # BTC地址生成 ✅
│   ├── performance.rs        # 性能统计工具 ✅
│   ├── crypto/               # CPU端加密算法 ✅
│   └── opencl/               # OpenCL模块 ✅
│       ├── mod.rs            # OpenCL模块入口 ✅
│       ├── context.rs        # OpenCL上下文管理 ✅
│       └── gpu_searcher.rs   # GPU搜索器 ✅
├── kernels/                  # OpenCL内核文件 ✅
│   ├── bip39/
│   │   ├── checksum.cl       # BIP39校验位验证 ✅
│   │   ├── entropy.cl        # 熵值计算 ✅
│   │   ├── mnemonic.cl       # 助记词生成 ✅
│   │   └── wordlist.cl       # 单词表管理 ✅
│   ├── crypto/
│   │   ├── pbkdf2.cl         # PBKDF2-HMAC-SHA512 ✅
│   │   ├── ripemd160.cl      # RIPEMD160哈希 ✅
│   │   ├── secp256k1.cl      # secp256k1椭圆曲线 ✅
│   │   ├── sha256.cl         # SHA256哈希 ✅
│   │   └── sha512.cl         # SHA512哈希 ✅
│   ├── base58.cl             # Base58编码 ✅
│   ├── debug.cl              # 调试内核 ✅
│   └── search.cl             # 主搜索内核 ✅
├── data/
│   └── english.txt           # BIP39单词表（2048词）
└── tests/                    # 测试套件 ✅
    ├── gpu_common.rs         # GPU测试工具模块
    ├── test_gpu_search.rs    # GPU搜索测试
    ├── test_gpu_debug.rs     # GPU调试测试
    ├── test_gpu_performance.rs  # GPU性能测试
    └── test_gpu_comprehensive.rs  # GPU综合测试
```

## 核心特性

### GPU内完整匹配
所有计算在GPU内完成，避免CPU-GPU数据传输瓶颈：
1. 助记词解码
2. 校验位验证（过滤93.75%无效计算）
3. PBKDF2-HMAC-SHA512（2048轮）
4. 主私钥派生
5. secp256k1公钥计算
6. SHA256 + RIPEMD160 → 公钥哈希
7. 与目标地址哈希对比

### 性能优化
- **校验位预过滤**：减少93.75%计算量
- **哈希直接对比**：避免Base58编码开销
- **动态索引计算**：GPU端实时计算候选词索引，内存占用降低99%
- **Salt预计算**：避免GPU端重复字符串拼接
- **Constant Memory**：单词表预加载到GPU高速缓存
- **循环展开**：提升PBKDF2吞吐量
- **性能统计**：实时显示H/s、KH/s、MH/s搜索速度

### 智能搜索空间管理
- **自动限制**：默认500万次遍历上限，防止意外长时间运行
- **超限保护**：超过限制时显示详细错误信息并安全退出
- **灵活配置**：通过`--max-search-space`参数自定义限制
- **大空间警告**：超过100万组合时提前预警

### 空数组智能处理
- 配置中`[]`表示使用该位置的全部2048个BIP39单词
- 自动计算搜索空间：各位置候选词数量的乘积
- 最后一位(word11)会被BIP39校验位自动过滤，实际只需计算1/32

## 使用示例

### 示例1：精确匹配已知助记词

```yaml
# config/known.yaml
mnemonic_size: 12
passwords: ["mypass"]
target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs"
word_positions:
  word0: ["abandon"]
  word1: ["ability"]
  word2: ["able"]
  # ... 其他位置都精确指定
  word11: ["about"]
```

### 示例2：部分不确定的助记词

```yaml
# config/uncertain.yaml
mnemonic_size: 12
passwords: []
target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs"
word_positions:
  word0: ["abandon", "ability", "able"]  # 3个候选
  word1: []  # 不确定，使用全部2048个词
  word2: ["about", "above", "absent"]    # 3个候选
  # ... word3-word10
  word11: []  # 最后一位会被校验位过滤
```

搜索空间 = 3 × 2048 × 3 × 1^9 × (2048/32) ≈ 1,179,648 次尝试

### 示例3：猜谜线索搜索

根据猜谜游戏线索，为每个位置配置高概率候选词：

```yaml
# config/puzzle.yaml
mnemonic_size: 12
passwords: ["", "btc", "bitcoin"]  # 尝试多个密码
target_address: "1YourTargetAddressHere"
word_positions:
  word0: ["abandon", "ability", "able", "about", "above"]
  word1: ["absent", "absorb", "abstract", "absurd", "abuse"]
  # ... 根据线索配置其他位置
  word11: []  # 让校验位自动过滤
```

## 性能报告示例

```
============================================================
GPU搜索性能报告
============================================================
初始化时间: 2.345 秒
GPU执行时间: 0.412 秒
总耗时: 2.757 秒
总尝试次数: 54060 次
搜索速度: 131214 H/s
搜索速度: 131.21 KH/s
平均每次尝试: 7621 纳秒
============================================================

✅ 找到 1 个匹配的助记词！

匹配 #1
  工作项索引: 12345
  助记词: abandon ability able about above absent absorb abstract absurd abuse access accident
  密码: mypass
```

## 测试

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test --test test_gpu_search

# 查看详细输出
cargo test -- --nocapture
```

**测试覆盖：**
- ✅ 40个测试用例全部通过
- ✅ GPU搜索功能测试（简单搜索、大空间、密码、错误词）
- ✅ GPU性能统计测试
- ✅ GPU调试功能测试
- ✅ 综合场景测试（12/15/18/24位助记词、带/不带密码、干扰词）

## 配置参考

### word_positions配置规则

1. **键名格式**：使用`word0`, `word1`, ..., `word11`（0-based索引）
2. **空数组**：`[]`表示使用该位置的全部2048个BIP39单词
3. **候选词**：`["word1", "word2"]`指定具体候选词
4. **搜索空间**：总组合数 = 各位置候选词数量的乘积
5. **校验位过滤**：最后一位(word11)只有1/32的词能通过校验

### 搜索空间计算示例

```yaml
word0: ["abandon", "ability"]     # 2个候选
word1: []                          # 2048个候选（全部）
word2: ["able", "about", "above"] # 3个候选
word3-word10: ["word"]             # 各1个候选（精确匹配）
word11: []                         # 2048个候选，但校验位过滤后只剩64个
```

总搜索空间 = 2 × 2048 × 3 × 1^8 × 64 = **786,432** 次尝试

## 参考项目

- [rust-profanity](https://github.com/gxj1994/rust-profanity) - 以太坊靓号地址搜索系统

## 许可证

MIT
