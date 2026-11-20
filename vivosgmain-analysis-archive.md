# libvivosgmain.so 分析归档

- 归档日期：2026-11-20
- 分析对象：`libvivosgmain.so`（vivo 安全 SDK，包内路径 `jni/share/security_cryptor.cpp`，构建时间 `Oct 15 2020 16:35:39`）
- 分析方式：静态分析（IDA Pro 9.4 + ida_mcp）＋ 设备侧动态 dump（Frida）＋ dump 回填 IDB
- 结论标注约定：**已确认**＝有 IDB 地址/字节或 dump 产物直接支撑；**推测**＝未取得直接证据，仅说明可能性

---

## 1. 样本信息

| 项目 | 值 | 依据 |
|---|---|---|
| 文件名 | `libvivosgmain.so` | 文件系统 |
| 路径 | `F:\source\vivobrowser\base\lib\arm64-v8a\libvivosgmain.so` | — |
| 大小 | `298,320` 字节（`0x48D50`） | 文件读取 |
| 架构 | ELF64，Little Endian，`ET_DYN`，`e_machine=183`（AArch64） | ELF header |
| MD5 | `0162e11b067365267d8af96959531e9f` | `hashlib.md5` |
| SONAME | `libvivosgmain.so` | `DT_SONAME` |
| 依赖库 | `liblog.so`、`libc.so`、`libm.so`、`libstdc++.so`、`libdl.so` | `DT_NEEDED`（5 项，偏移见 §2） |
| 入口点 | `e_entry = 0x66E0`（运行时 `0x7E662076E0`） | ELF header |
| 导出数（本次复核） | 216 个已定义符号：101 FUNC + 108 OBJECT + 7 NOTYPE | `.dynsym`（`DT_SYMTAB=0x908`，`DT_HASH.nchain=255`） |
| 导入数 | 36 个具名未定义符号：34 FUNC + 2 OBJECT | 同上 |

### 加固特征（已确认）

1. **节头表被裁剪/伪造**：`e_shoff=0x48C50`、`e_shnum=4`、`e_shstrndx=1`，但第 1 项是 `SHT_NOBITS`、`sh_offset=0`、`sh_size=文件长度`，节名全部不可解析；表中没有 `.symtab/.strtab`，只有疑似 `.dynsym`（`type=3`，`addr=0x20F0`，`link=0`，`entsize=0`，`size=0x1173` 非 24 的整数倍）与 `.dynamic`。→ **静态符号表被剥离，节头是残桩**。
2. **导出名混淆**：导出对象里存在 `x55`、`y64`、`x`、`y24` 这类无意义短名（共 108 个 OBJECT 导出，其中 21 个为 WEAK）。
3. **代码段加密**：原文件中 `0x6000`–`0x26000` 区间 33 个 4 KB 块熵均为 `7.41–7.79`（整文件熵仅 `4.912`）；`JNI_OnLoad` 所在 `0x1C33C` 处首 4 字节为 `AC 0E A3 65`，窗口熵 `7.707` → 该区间是密文，运行时才解密。
4. **动态表被裁剪**：文件内 `PT_DYNAMIC`（vaddr `0x56A70`，文件偏移 `0x48AF0`，大小 `0x1E0`）只有 6 项：5 个 `DT_NEEDED` + `DT_SONAME` + `DT_NULL`，**没有 `DT_STRTAB/DT_SYMTAB/DT_HASH/DT_INIT/DT_RELA`**；而运行时 dump 的同一 `PT_DYNAMIC` 有 26 项且标签完整（见 §3）。→ 文件中的动态表不是可加载形态，运行时由壳/加载流程补齐（**具体补齐机制未完全确认，属推测**）。

> 补充：`.so` 尾部 `0x48078`–`0x48AD4` 是另一段 `PT_LOAD`（vaddr `0x6A078`，RX，`filesz=0xA5C`），`0x48410` 起为该段内的 A64 代码，并非“游离于所有 PT_LOAD 之外”。

---

## 2. 静态分析阶段结论

### 2.1 程序头（5 个）

| # | 类型 | 权限 | 文件偏移 | vaddr | filesz | memsz |
|---|---|---|---|---|---|---|
| 0 | `PT_LOAD` | R+X | `0x0` | `0x0` | `0x274C8` | `0x451E4` |
| 1 | `PT_LOAD` | R+W | `0x45B60` | `0x55B60` | `0x2060` | `0x14078` |
| 2 | `PT_DYNAMIC` | R+W | `0x48AF0` | `0x56A70` | `0x1E0` | `0x1E0` |
| 3 | `PT_GNU_EH_FRAME` | R | `0x40998` | `0x40998` | `0xA2C` | `0xA2C` |
| 4 | `PT_LOAD` | R+X | `0x48078` | `0x6A078` | `0xA5C` | `0xA5C` |

`PT_LOAD#0` 的 `memsz` 比 `filesz` 大 `0x1DD1C`，即 vaddr `0x274C8` 之后是大片 BSS；`PT_LOAD#1` 同理（`memsz-filesz = 0x12018`）。**JNI 方法表、字符串池、RSA 常量都落在这两段 BSS 里**，原文件没有内容。

### 2.2 符号表

- **无 `.symtab`**（节头表里没有 `SHT_SYMTAB`，节名也不可解析）。
- 动态符号表存在：`DT_SYMTAB=0x908`、`DT_STRTAB=0x20F0`、`DT_STRSZ=0x1173`、`DT_SYMENT=0x18`、`DT_HASH=0x1F0`，`nchain=255`。
- 255 项中：第 0 项为空；**未定义具名符号 36 个**（34 个 FUNC：`malloc/free/memcpy/strlen/__android_log_print/__stack_chk_fail/__cxa_*` 等；2 个 OBJECT：`__sF`、`__stack_chk_guard`）。
- **已定义导出 216 个**：101 FUNC（大量 C++ 运行时符号，如 `__cxa_demangle`、`_Unwind_*`）、108 OBJECT（87 GLOBAL + 21 WEAK，含混淆短名 `x55/y64`）、7 NOTYPE。
- 差异说明：早期报告记“204 个导出”，本次按 `.dynsym` 逐项复核为 **216**（216−101 FUNC−108 OBJECT=7 NOTYPE）。两个口径的差异**尚未定位**（推测与 WEAK 符号/重名去重有关），归档以 216 为准并保留 204 备查。

### 2.3 入口点与 `.init_proc` 自解密链路

- `e_entry = 0x66E0`（运行时 `0x7E662076E0`），入口指令为：

```
ADRL X0, unk_7E66258000     ; BSS 中的解包/数据区
B    sub_7E662072D0         ; GOT/PLT 跳板
```

- `DT_INIT = 0x6A098`（运行时 `0x7E6626B098`），即 `.init_proc`。
- `.init_proc` 的职责是自解密：
  - `sub_7E6626B73C` 为解密循环；
  - `loc_7E6626B514` 为解密后跳转/收尾块；
  - 未发现 `DT_INIT_ARRAY`（运行时动态表中 `DT_INIT_ARRAYSZ` 存在但对应数组内容为空/未使用），也没有 C++ 全局构造函数参与初始化。
- 结论：**壳在 `.init_proc` 阶段把 `0x6000`–`0x26000` 的密文代码就地解密，然后才执行真正的库逻辑**。因此静态反编译看到的 `JNI_OnLoad` 在未 dump 前是密文，无法直接还原。

### 2.4 代码段高熵证据

| 区域 | 熵 | 说明 |
|---|---|---|
| 整文件 | 4.912 | 大量零填充/BSS |
| `0x0`–`0x451E4`（seg1） | 4.997 | 含密文区与零区 |
| `0x1C33C` 起 4 KB | **7.707** | `JNI_OnLoad` 密文窗口 |
| `0x6000`–`0x26000` | **7.41–7.79**（33 个块全部 >7.0） | 加密代码主体 |
| 解密后 `JNI_OnLoad` 窗口 | **6.77** | dump 后实测（`meta.json`） |

---

## 3. 动态 dump

### 3.1 为什么必须动态

1. 代码段在文件里是密文（熵 7.7+），静态反编译无意义；
2. `JNI` 方法表、方法名字符串、RSA DER 常量位于 BSS（文件 `filesz` 不覆盖），静态文件里**根本不存在**；
3. 文件内 `PT_DYNAMIC` 缺 `DT_STRTAB/DT_SYMTAB/DT_HASH` 等关键标签，静态解析无法得到真实导入/导出视图。

### 3.2 静默解密判断依据（双条件）

- 条件 A：`JNI_OnLoad` 首 4 字节不再等于样本密文头 `AC 0E A3 65`；
- 条件 B：同一地址起 4 KB 窗口熵 `< 7.0`（密文≈7.7，解密后实测 6.77）；
- 附加合理性检查：首两字节不能同时为 `00` 或 `FF`。
- 轮询间隔 100 ms（探测）/20 ms（等待模块），最长等待解密 60 s。

### 3.3 dump 参数（三段）

| 段 | 模块内偏移（vaddr） | 大小（memsz） | 权限 | 产物 |
|---|---|---|---|---|
| seg1 | `0x00000` | `0x451E4` | R+X | `seg1_code.bin` |
| seg2 | `0x55B60` | `0x14078` | R+W | `seg2_data.bin` |
| seg3 | `0x6A078` | `0x00A5C` | R+X | `seg3_plt.bin` |

- 运行时基址：`0x7E66201000`（`base.txt`）。
- 模块总大小：`438272`（`0x6B000`）。
- 额外产物：3 个匿名可执行段 dump（`anon_7ef06f1000_73728.bin`、`anon_97f32000_33554432.bin`、`anon_7f801ad000_4096.bin`）。

### 3.4 Frida 方案要点（`sgdump.js`）

- **零 Interceptor**：只用 `Process.findModuleByName` + 轮询 `Memory.readByteArray`，避免 inline hook 触发反调试/反注入。
- `readSafe()` 按 `Process.findRangeByAddress` 分块读取，未映射区域补零，避免整段读取失败。
- 解密判定用“首字节 + 熵”双条件（见 3.2）。
- 在 `rpc.exports.redump` 中暴露重跑入口，无需重启进程即可二次 dump。
- 匿名可执行段过滤：只保留无 `file` 映射、大小在 `0x1000`–64 MB、且不与模块自身重叠的区间。

### 3.5 产物与校验

| 文件 | 大小 | 说明 |
|---|---|---|
| `seg1_code.bin` | `0x451E4` | 代码段（已解密） |
| `seg2_data.bin` | `0x14078` | 数据/BSS 段（含方法表、字符串、RSA DER） |
| `seg3_plt.bin` | `0x00A5C` | 第二代码段（PLT/辅助代码） |
| `base.txt` | — | `0x7e66201000` |
| `meta.json` | — | `decrypted=true, head=fc6fbaa9, entropy=6.77` |

校验（`sgverify.py`）：

```
seg1 size = 0x451E4（与 memsz 一致）
head = fc6fbaa9（≠ AC0EA365）
entropy = 6.77（< 7.0）
prologue 检查通过
→ [PASS] 可以回填 IDA
```

---

## 4. 回填 IDA

### 4.1 操作步骤（`ida_apply_dump.py`）

1. 读取 `base.txt` 得到运行时基址 `0x7E66201000`；
2. `ida_segment.rebase_program(BASE - cur, 0)` 重定基，使 IDB 地址与 dump 中的绝对地址一致；
3. 逐段 `ida_bytes.patch_bytes(BASE + off, dump_bytes)` 写回三段；
4. 段权限：代码段置 `RX`，数据段置 `RW`；
5. 对 `JNI_OnLoad` 地址做 `del_items` + `auto_wait()`，再 `add_func` 并反编译验证。

### 4.2 注意事项

- **不要重复应用 `.rela`**：dump 是进程内已重定位后的内存镜像，指针已是绝对地址；再跑一遍重定位会把指针二次加基址，直接损坏表/字符串/函数指针。
- **不要用文件里的 `.rela` 重建导入**：运行时 `DT_*` 已被加载器改写，文件版动态表又是残桩，二者混用会得到错误的导入/导出视图。
- dump 回填后 IDA 的“导出表”视图可能不完整（本次会话中曾出现导出识别数异常偏低），**统计请直接解析 `.dynsym`（`DT_SYMTAB/DT_HASH`），不要依赖 IDA 的 Exports 窗口**。
- 33 个 native 函数中部分入口落在原分析 chunk 中间，`add_func` 会失败：先 `del_func` 掉覆盖它的大函数，再逐入口 `create_insn` + `add_func`。
- 建议保留一份未回填备份（`libvivosgmain_dumpbackup.i64`），便于对照。

---

## 5. `JNI_OnLoad` 结论

函数：`JNI_OnLoad @ 0x7E6621D33C`（`0x7E6621D33C`–`0x7E6621DB78`），被控制流平坦化 + 不透明谓词包裹。

| 步骤 | 地址 | 行为 |
|---|---|---|
| GetEnv | `0x7E6621D4AC` | `vm->GetEnv(vm, &env, 0x10004)`，版本 **JNI_VERSION_1_4**（65540） |
| GetEnv（另一分支） | `0x7E6621DB28` | 状态机中的重复取 env |
| FindClass | `0x7E6621D958` | `env->FindClass("com/vivo/security/jni/SecurityCryptor")`；类名字符串位于 `0x7E66258830`（BSS，运行时写入） |
| RegisterNatives | `0x7E6621D8FC` | `env->RegisterNatives(clazz, 0x7E66258880, 33)`，vtable 偏移 `0x6B8`（index 215） |
| DeleteLocalRef | `0x7E6621D82C` | `env->DeleteLocalRef(clazz)`，偏移 `0xB8`（index 23） |
| 取上下文对象 | `0x7E6621D838` | `sub_7E6621DB78(env)` |
| NewGlobalRef | `0x7E6621DA8C` | `qword_7E66258BC8 = env->NewGlobalRef(obj)`，偏移 `0xA8`（index 21） |
| 调用 nativeSecurityInit#1 | `0x7E6621DAAC` | `sub_7E6621E140(env, 0, obj, 0, 0, 0)` |

### 返回值与失败路径

- 成功：`n65540 = 0x10004`（`0x7E6621D7F0`），即返回 `JNI_VERSION_1_4`。
- 失败：统一状态 `LABEL_24` 置 `n65540 = -1`（`0x7E6621D788`），覆盖：
  - `GetEnv` 返回非 0；
  - `FindClass` 返回 `nullptr`；
  - `RegisterNatives` 返回负值（`0x7E6621D900` 起对返回值做符号测试）；
  - `sub_7E6621DB78` / `nativeSecurityInit#1` 的失败分支。
- 失败时还会走 `sub_7E66207300(6)` 打日志（日志串在栈上逐字节拼出，如 `"..._t check_s faile"`、`"nativeSecurityIniV_SecurityNativ"`，用于规避静态字符串检索）。

---

## 6. 33 个 native 方法表

### 6.1 表布局

```c
typedef struct {
    const char *name;       /* +0  */
    const char *signature;  /* +8  */
    void       *fnPtr;      /* +16 */
} JNINativeMethod;          /* sizeof = 24 (0x18)，AArch64 无填充 */
```

- 表地址：`0x7E66258880`
- 项数：33，总长 `33 × 24 = 792 = 0x318`
- 表尾：`0x7E66258B98`
- 表前 0x50 字节处（`0x7E66258830`）是类名字符串 `com/vivo/security/jni/SecurityCryptor`

### 6.2 完整方法表（name / signature / fnPtr）

| # | name | signature | fnPtr |
|---|---|---|---|
| 0 | nativeSecurityInit | `(Landroid/content/Context;Ljava/io/FileDescriptor;JJ)I` | `0x7E6621E140` |
| 1 | nativeFreeResource | `()Z` | `0x7E6621E438` |
| 2 | nativeGetSignatures | `(Landroid/content/Context;)Ljava/lang/String;` | `0x7E6621E484` |
| 3 | nativeCheckSignatures | `()Z` | `0x7E6621EC64` |
| 4 | nativeGetRsaPublicKey | `()[B` | `0x7E6621ED24` |
| 5 | nativeGetRsaPrivateKey | `()[B` | `0x7E6621EEAC` |
| 6 | nativeAesEncrypt | `([BI)[B` | `0x7E6621F02C` |
| 7 | nativeAesDecrypt | `([BI)[B` | `0x7E6621F4C8` |
| 8 | nativeAesEncrypt | `([B[BI)[B` | `0x7E6621F988` |
| 9 | nativeAesDecrypt | `([B[BI)[B` | `0x7E6621FE98` |
| 10 | nativeBase64Encrypt | `([B)[B` | `0x7E662204E0` |
| 11 | nativeBase64Decrypt | `([B)[B` | `0x7E66220818` |
| 12 | nativeWaveStringNet | `(Ljava/lang/String;)J` | `0x7E66220B90` |
| 13 | arg0 | `(Landroid/content/Context;)Ljava/lang/String;` | `0x7E6622130C` |
| 14 | arg1 | `(Landroid/content/Context;)Ljava/lang/String;` | `0x7E6622147C` |
| 15 | arg2 | `(Landroid/content/Context;)Ljava/lang/String;` | `0x7E662215CC` |
| 16 | waveString | `(Ljava/lang/String;)Ljava/lang/String;` | `0x7E6622171C` |
| 17 | waveStringEnd | `(Ljava/lang/String;)Ljava/lang/String;` | `0x7E66221A08` |
| 18 | nativeSecurityInit | `()Z` | `0x7E66221DA4` |
| 19 | nativeSetPackageName | `([BI)Z` | `0x7E66221E54` |
| 20 | nativeSetSystemSignatures | `([BI)Z` | `0x7E66222054` |
| 21 | nativeSetOldSystemSignatures | `([BI)Z` | `0x7E66222250` |
| 22 | nativeSetSecuritySystemSignatures | `([BI)Z` | `0x7E66222438` |
| 23 | nativeSetTestKeySystemSignatures | `([BI)Z` | `0x7E66222624` |
| 24 | nativeSetNewTestKeySystemSignatures | `([BI)Z` | `0x7E66222868` |
| 25 | nativeSetSharedSignatures | `([BI)Z` | `0x7E66222A4C` |
| 26 | nativeSetMediaSignatures | `([BI)Z` | `0x7E66222C14` |
| 27 | nativeSetAppIotSignatures | `([BI)Z` | `0x7E66222DF4` |
| 28 | nativeSetAppSignatures | `([BI)Z` | `0x7E66222FE4` |
| 29 | nativeSetAesKey | `([BI)Z` | `0x7E662231AC` |
| 30 | nativeSetRsaKey | `([BI[BI)Z` | `0x7E66223374` |
| 31 | nativeGenerateFile | `([BI)Z` | `0x7E6622362C` |
| 32 | getCipher | `(I)Ljavax/crypto/Cipher;` | `0x7E66223680` |

说明：索引 13–15 的名字就是 `arg0/arg1/arg2`（不是重命名失误）；索引 6/7 与 8/9 是两组同名重载。

### 6.3 字符串与表在 BSS、明文、运行时写入

- name/signature 指向的字符串位于 `0x7E66258400`–`0x7E66258830` 的紧凑字符串池，**内存中就是明文 ASCII**：
  - `0x7E66258410`：`6e 61 74 69 76 65 53 65 63 75 72 69 74 79 49 6e 69 74 00` → `nativeSecurityInit`
  - `0x7E66258430`：`28 4c 61 6e 64 72 6f 69 64 2f ...` → `(Landroid/content/Context;Ljava/io/FileDescriptor;JJ)I`
  - `0x7E66258483`：紧跟在 `nativeFreeResource` 的 NUL 后，内容 `28 29 5a 00` → `()Z`
- 这些地址全部落在 `PT_LOAD#1` 的 BSS（文件只覆盖到 vaddr `0x57BC0`，而字符串在 `0x58410`、表在 `0x58880`）。对原文件全文检索：`nativeSecurityInit` 明文 0 处、XOR-0x78 编码 0 处、类名 0 处。
- 运行时由壳代码逐字节写入，例如 `0x7E6622473C` 处的 `STRB W23, [X28, #aNativesecurity]`（xref type=2，写 `0x7E66258410` 首字节 `'n'`）；字符虽由 `BIC/AND/ORR/EOR` 拆分常量即时算出，**落盘结果仍是明文**，之后没有二次解码。
- **结论**：IDA 里“名字像乱码”不是字符串被编码，而是：① 表里是 8 字节绝对地址（如 `10 84 25 66 7e 00 00 00`）；② 未 dump 时 BSS 为空/未定义，IDA 只显示 `unk_`/`byte_`。

---

## 7. AES 实现分析

### 7.1 结构

- 核心函数：`sub_7E66209B50(in, len, out, rk, keyBits, iv)`
  - `v10 = len >> 4`；
  - `if (((len ^ ~0xF) & len) != 0) return 0;` → **要求长度为 16 的整数倍**；
  - CBC 循环：前一块密文作为下一块 IV，首块用传入 IV；
  - **函数本身不做去填充**，去填充在调用方。
- 固定 IV：`xmmword_7E66258870` = `00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`（与表地址只差 `0x10`，故 `JNI_OnLoad` 用 `ADD X9, X9, #0x10` 得到表地址）。
- 密钥扩展：`sub_7E6620B410(key, out, keyBits)`，参数是**密钥位数**（128/192/256），按 `keyBits` 选择轮数/字扩展路径。
- 标准 AES 实现：标准 S-box/逆 S-box、InvMixColumns、Rcon 都在代码中；**未发现白盒查表/密钥嵌入表的白盒 AES 特征** → **非白盒**。混淆手段是控制流平坦化与不透明谓词，不是密码学层面的白盒。

### 7.2 默认密钥与派生

`sub_7E66217990`（唯一调用者为 `sub_7E66215758`）在栈上构造 32 字节种子：

```
89 47 DD 41 A8 F2 C9 F4 C2 02 BB 3A 9E DB A2 9B 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78
```

用 `sub_7E66217E54` 逐字节 `^ 0x78`（指令层被拆成 `BIC/AND/ORR + EOR #0x3C`，等价 `^0x78`）得到：

```
f1 3f a5 39 d0 8a b1 8c ba 7a c3 42 e6 a3 da e3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

即 **默认密钥 = `f13fa539d08ab18cba7ac342e6a3dae3` + 16 个 `00`**（32 字节）。结果写入：
- `ctx+0x88`：`STUR Q0`（`0x7E66217A58`）
- `ctx+0x98`：`STUR Q0`（`0x7E66217A50`）

同一函数还把包名 `"com.vivo.securitysdkdemo"` 写入 `ctx+0x80`（**不参与密钥派生**），并把两段 DER（162 B 公钥、635 B 私钥）写入 `ctx+0xA8/0xB0`。

### 7.3 去填充与完整性

`nativeAesDecrypt`（`0x7E6621F4C8` / 重载 `0x7E6621FE98`）在 CBC 解密后：

```c
n = out[len-1];
v5 = (n != 0 && n <= 0x10) ? len - n : len;   // 只看最后一个字节
```

- **只校验末字节范围**，不检查前 `n-1` 个填充字节是否都等于 `n`；
- 若末字节为 0 或 >16，则**不截断**，原样返回全部密文长度；
- **无 MAC/HMAC/签名校验**，不提供完整性保护，可被篡改/填充预言攻击（仅从算法层结论）。

---

## 8. 密钥来源排查（`ctx+0x88`）

### 8.1 两个写入点（已确认）

| 写入点 | 函数 | 方式 | 触发路径 |
|---|---|---|---|
| `0x7E66217A58` / `0x7E66217A50` | `sub_7E66217990` | `STUR Q0` 写 32 字节 | `sub_7E66215758` ← `nativeSecurityInit#1`（`0x7E6621E2F4`） |
| `0x7E66219668` | `sub_7E66219604` | `STRB` 逐字节，`for(i<len) ctx[0x88+i]=buf[i]` | `sub_7E66216958` ← `nativeSetAesKey`（`0x7E662231AC`） |

`ctx` 全局指针 `qword_7E66258BC0` 只有 3 个写点：`0x7E66215840`（新建）、`0x7E662158F0`（销毁）、`0x7E66215A44`（无参 init 新建）。

### 8.2 无参 init 导致全零密钥

- `nativeSecurityInit#1`（`0x7E6621E140`）：取 `env`/`fd` → `sub_7E6621C1F0` → `qword_7E66258BD0` → `DeleteLocalRef` → `sub_7E66215758()`（新建 ctx 并派生默认密钥）→ `sub_7E66215BC8`。
- `nativeSecurityInit#2`（`0x7E66221DA4`）→ `sub_7E66215A44()`：只有 `malloc(184)` + `memset` + 旧对象销毁 + 写全局指针，**不调用 `sub_7E66217990`** → 该路径下 `ctx+0x88` 全为 0。
- 因此：进程只调无参 init 时，AES 密钥为 32 个 `00`。

### 8.3 `nativeSetAesKey` 的风险

`nativeSetAesKey` 流程：`GetByteArrayElements` → `malloc(len+1)` → `memcpy` → `sub_7E66216958(key, len)` → `free` → `ReleaseByteArrayElements`，返回 1/0。

- `sub_7E66219604` 的循环为 `for (i = 0; i < len; i++) *(ctx + 0x88 + i) = buf[i];`，**没有 `len <= 32` 的上限校验**；
- Java 侧传入超过 32 字节会越界写 `ctx+0xA8` 及之后的字段（公钥指针/DER 区），属于内存破坏风险。

### 8.4 Java 侧找不到调用的可能原因（推测）

1. 调用被放在其他 native 库/进程初始化路径中，通过 `dlsym`/`RegisterNatives` 间接调用；
2. Java 代码经加固（dex 抽取/方法抽取）后，反编译视图里看不到真实调用；
3. 由服务端下发配置后通过反射/JNI 调用（方法名在运行时拼接）；
4. SDK 版本与当前反编译的 Java 层不匹配（demo 包 `com.vivo.securitysdkdemo` 与实际集成方不一致）。

以上均未取得直接证据，**属推测**；需要在设备侧下断点/插桩确认。

---

## 9. 实际解密验证

密文（32 字节）：

```
64 e4 a7 21 59 7f ee 9e 38 38 7d 94 7f 01 bd d3
de f2 2b e7 37 6b 83 fc 83 95 11 fe c0 0b 3d 89
```

IV：`00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F`（`0x7E66258870`）。

| 参数 | 密钥 | 解密结果 | 末字节/填充 | 结论 |
|---|---|---|---|---|
| AES-256-CBC | `f13fa539d08ab18cba7ac342e6a3dae3` + 16×`00` | `2be2cc55d562fae8975e84d7f9d3343a5bfa035a508e40729fc604119a6f3ccf` | 末字节 `0xCF`（>16） | 不截断，返回 32 字节不可读数据；填充不是 `02 02`；密钥/版本不匹配 |
| AES-128-CBC | `f13fa539d08ab18cba7ac342e6a3dae3` | `e5a4a7e8bf9ee69ab4e99ba8e5a4aae5a4b8e5bca0e4ba86` + `08×8` | 末字节 `0x08` | 明文 `大连暴雨太夸张了`（24 字节），标准 PKCS#7，去填充后正确 |

判定依据：

- AES-128 结果 24 字节全部是合法 UTF-8 中文，且后 8 字节严格为 `08 08 08 08 08 08 08 08`，符合 PKCS#7（块长 16，明文 24 → 填充 8）；
- AES-256 结果无任何可读结构，末字节 `0xCF` 不满足 `0 < n <= 16`，SDK 的“只看末字节”逻辑不会截断，输出 32 字节乱码；
- 由此确认：**`nativeAesDecrypt` 的第二个参数是 keyBits（128/192/256），不是数据长度**；该密文对应的是 128 位密钥档，且实际密钥就是默认派生密钥的前 16 字节。

---

## 10. 脚本清单

| 脚本 | 位置 | 用途 |
|---|---|---|
| `sgdump.js` | `C:\Users\Administrator\Desktop\1\sgdump.js` | Frida dump 脚本：等待模块、熵+首字节判定解密、dump 三段、dump 匿名可执行段、`rpc.redump` 重跑（全文见附录 B） |
| `sgrun.py` | `C:\Users\Administrator\Desktop\1\sgrun.py` | 驱动脚本：`spawn`/`attach` 目标、连接远程 frida-server（默认 `127.0.0.1:27043`）、等待 `done`、`adb pull` 产物、写 `base.txt`/`meta.json`（全文见附录 C） |
| `sgverify.py` | `C:\Users\Administrator\Desktop\1\sgverify.py` | 产物校验：seg1 大小、首 4 字节 ≠ `AC0EA365`、窗口熵 <7.0、A64 prologue、匿名段熵（全文见附录 D） |
| `ida_apply_dump.py` | `C:\Users\Administrator\Desktop\1\ida_apply_dump.py` | 回填 IDB：重定基到 `0x7E66201000`、patch 三段、修段权限、`del_items`+`auto_wait`、`add_func`+反编译验证（全文见附录 E） |
| IDAPython 修复脚本 | 见附录 A | 定义 `JNINativeMethod`、给表应用类型、按 name 重命名 fnPtr、给 fnPtr 建函数 |
| 产物目录 | `C:\Users\Administrator\Desktop\1\sg_dump` | `base.txt`、`meta.json`、`seg1_code.bin`、`seg2_data.bin`、`seg3_plt.bin`、3 个 anon dump |

IDB：

- 回填后：`F:\source\vivobrowser\base\lib\arm64-v8a\libvivosgmain.so.i64`（imagebase `0x7E66201000`）
- 回填前备份：`libvivosgmain_dumpbackup.i64`

---

## 11. 遗留事项

1. **设备侧验证真实密钥**：在 `nativeSetAesKey`（`0x7E662231AC`）与 `sub_7E66219604`（`0x7E66219668`）下断点，确认运行时 `len` 与写入内容；确认 Java 侧调用来源（`dlsym`/反射/其他 so）。
2. **匿名段未分析**：3 个 `anon_*` dump 已产出但未解析，可能包含壳的二次解包产物或 JIT 代码。
3. **重载方法未逐个反编译**：`nativeAesEncrypt/nativeAesDecrypt` 的两组重载（`0x7E6621F02C`/`0x7E6621F4C8` 与 `0x7E6621F988`/`0x7E6621FE98`）只分析了其中一组，差异（是否带 keyBits、是否走 ctx 密钥）待确认。
4. **`nativeCheckSignatures`（`0x7E6621EC64`）未拆**：签名校验算法、比对对象、返回值语义未分析。
5. **`nativeGenerateFile`（`0x7E6622362C`）、`waveString/arg0-2`、`nativeWaveStringNet`** 未展开。
6. **导出数口径差异**：204（历史）vs 216（本次 dynsym 复核），需用同一工具再核一次。
7. **壳补齐动态表的机制**未确认：文件 `PT_DYNAMIC` 仅 6 项，运行时 26 项，补齐发生在何时/由谁完成尚无直接证据（推测为壳的加载阶段）。
8. **IDA 导出视图异常**：回填后 IDA 的 Exports 窗口数量明显偏少，尚未定位原因；统计请以 `.dynsym` 为准。

---

## 12. 关键地址索引

### 12.1 样本/ELF

| 地址/偏移 | 作用 |
|---|---|
| `0x0` | `PT_LOAD#0`（RX）起始；vaddr 0 |
| `0x66E0` | `e_entry`（运行时 `0x7E662076E0`） |
| `0x1C33C` | `JNI_OnLoad` 在文件/模块内的偏移（运行时 `0x7E6621D33C`） |
| `0x274C8` | `PT_LOAD#0` 文件覆盖结束（之后为 BSS） |
| `0x45B60` / `0x55B60` | `PT_LOAD#1` 文件偏移 / vaddr |
| `0x48AF0` / `0x56A70` | `PT_DYNAMIC` 文件偏移 / vaddr |
| `0x48078` / `0x6A078` | `PT_LOAD#4` 文件偏移 / vaddr（第二代码段） |
| `0x6A098` | `DT_INIT`（`.init_proc`，运行时 `0x7E6626B098`） |
| `0x908` | `DT_SYMTAB`（vaddr） |
| `0x20F0` | `DT_STRTAB`（vaddr） |
| `0x1F0` | `DT_HASH`（nchain=255） |
| `0x3268` / `0x2760` | `DT_RELA` / `DT_RELASZ` |
| `0x59C8` | `DT_JMPREL` |
| `0x56C50` | `DT_REL`（运行时） |

### 12.2 JNI 注册

| 地址 | 作用 |
|---|---|
| `0x7E6621D33C` | `JNI_OnLoad` |
| `0x7E6621D4AC` | `vm->GetEnv(..., 0x10004)` |
| `0x7E6621D958` | `FindClass("com/vivo/security/jni/SecurityCryptor")` |
| `0x7E66258830` | 类名字符串（BSS） |
| `0x7E6621D8FC` | `RegisterNatives(env, clazz, 0x7E66258880, 33)` |
| `0x7E6621D82C` | `DeleteLocalRef` |
| `0x7E6621DA8C` | `NewGlobalRef` → `qword_7E66258BC8` |
| `0x7E6621D7F0` | 成功返回值 `0x10004` |
| `0x7E6621D788` | 失败返回值 `-1` |
| `0x7E66258880` | `JNINativeMethod[33]` 表 |
| `0x7E66258B98` | 表尾（`+0x318`） |
| `0x7E66258400`–`0x7E66258830` | 方法名/签名/类名 字符串池 |
| `0x7E66258870` | 固定 IV `00..0F` |

### 12.3 密钥/上下文

| 地址 | 作用 |
|---|---|
| `qword_7E66258BC0` | 全局 `ctx` 指针 |
| `qword_7E66258BD0` | init 返回的上下文对象 |
| `qword_7E66258BC8` | `NewGlobalRef` 结果 |
| `0x7E66215758` | 新建 ctx（`malloc(184)`），调用 `sub_7E66217990` |
| `0x7E66215840` | 写 `qword_7E66258BC0` |
| `0x7E66217990` | 派生默认密钥（`STUR Q0` 写 `ctx+0x88`/`ctx+0x98`） |
| `0x7E66217E54` | `^0x78` 解码函数（全库 4 个 xref，均在 `0x7E66217990` 内） |
| `0x7E66219604` | 逐字节写 `ctx+0x88`（`STRB` @ `0x7E66219668`） |
| `0x7E66216958` | 密钥设置包装（唯一调用者 `nativeSetAesKey`） |
| `0x7E6621A430` | 从 `ctx+0x88` 复制 32 字节密钥（调用者 `sub_7E66216C94`） |
| `0x7E66216C94` | 取密钥包装（被 RSA 设置与 AES 加解密调用） |
| `0x7E66215A44` | 无参 init：只 `malloc/memset`，不派生密钥 |
| `0x7E662231AC` | `nativeSetAesKey` |
| `0x7E66223374` | `nativeSetRsaKey` |

### 12.4 AES/数据

| 地址 | 作用 |
|---|---|
| `0x7E66209B50` | AES-CBC 核心（加密/解密共用） |
| `0x7E6620B410` | 密钥扩展（按 keyBits 128/192/256） |
| `0x7E6621F4C8` | `nativeAesDecrypt ([BI)[B`（读 ctx 密钥） |
| `0x7E6621FE98` | `nativeAesDecrypt ([B[BI)[B` 重载 |
| `0x7E6621F02C` / `0x7E6621F988` | `nativeAesEncrypt` 两组重载 |
| `0x7E66258010` | 64 字符自定义 Base64 字母表 |
| `0x7E66258098` | 635 字节 XOR-0x78 → RSA 私钥 DER（`30 82 02 77 ...`） |
| `0x7E66258313` | 162 字节 XOR-0x78 → RSA 公钥 DER（`30 81 9F ...`） |
| `0x7E66258400` | `jni/share/security_cryptor.cpp`、构建时间串 |
| `0x7E6622473C` | 壳写方法名字符串的 `STRB` 点（`nativeSecurityInit` 首字节） |

---

## 附录 A：`JNINativeMethod` 修复脚本（IDAPython）

```python
import ida_typeinf, ida_bytes, ida_funcs, ida_name, idc

TABLE_BASE = 0x7E66258880
COUNT      = 33
ENTRY_SIZE = 24

# 1) 定义 JNINativeMethod 并写入类型库
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(
    tif, None,
    "struct JNINativeMethod { const char *name; const char *signature; void *fnPtr; };",
    ida_typeinf.PT_SIL)
tif.set_named_type(None, "JNINativeMethod")

# 2) 应用到整张表（33 * 24 = 0x318 字节）
ida_typeinf.apply_tinfo(TABLE_BASE, tif, ida_typeinf.TINFO_DEFINITE)

# 3) 逐项：读明文 name/sig，建函数，重命名，写注释
used = set()
for i in range(COUNT):
    ea      = TABLE_BASE + i * ENTRY_SIZE
    name_ea = ida_bytes.get_qword(ea)
    sig_ea  = ida_bytes.get_qword(ea + 8)
    fn_ea   = ida_bytes.get_qword(ea + 16)

    raw = ida_bytes.get_strlit_contents(name_ea, -1, 0)
    if not raw:
        continue
    name = raw.decode("utf-8", "replace")
    sig  = (ida_bytes.get_strlit_contents(sig_ea, -1, 0) or b"").decode("utf-8", "replace")

    idc.set_cmt(ea, "%s %s" % (name, sig), 0)

    if fn_ea and not ida_funcs.get_func(fn_ea):
        idc.create_insn(fn_ea)
        ida_funcs.add_func(fn_ea)

    base = "Java_com_vivo_security_jni_SecurityCryptor_" + name
    new, k = base, 2
    while new in used:            # 处理 nativeAesEncrypt/Decrypt 等重载
        new = "%s_%d" % (base, k)
        k += 1
    used.add(new)
    ida_name.set_name(fn_ea, new, ida_name.SN_FORCE | ida_name.SN_NOWARN)
```

已在当前回填 IDB 上验证前两步：表地址 flags 由 `0x9400`（普通字节）变为 `0x6000`（`FF_STRUCT`），反编译中 `&byte_7E66258880` 变为 `&stru_7E66258880`。

---

## 附录 B：`sgdump.js`

用途：设备侧 dump `libvivosgmain.so` 的代码段/数据段/PLT 段与匿名可执行段，内置“首字节 + 熵”解密判定和 `rpc.redump` 重跑入口。
运行：`frida -U -f <包名> -l sgdump.js --no-pause`，或由 `sgrun.py` 加载；产物写入设备 `/data/local/tmp/sgdump`。
依赖：Frida 16+（`frida`/`frida-tools`）、已 root 的 Android 设备与 `frida-server`、目标应用会加载 `libvivosgmain.so`。

```javascript
/*
 * sgdump.js — libvivosgmain.so 动态 dump
 * 设计原则：零 Interceptor，只用轮询 + Memory.readByteArray；
 *          解密判定用「熵 + 首字节」双条件。
 */
'use strict';

var CFG = {
  moduleName: 'libvivosgmain.so',
  outDir: '/data/local/tmp/sgdump',
  segs: [
    { off: 0x00000, size: 0x451E4, name: 'seg1_code.bin' },
    { off: 0x55B60, size: 0x14078, name: 'seg2_data.bin' },
    { off: 0x6A078, size: 0x00A5C, name: 'seg3_plt.bin' }
  ],
  jniOnLoadOffset: 0x1C33C,
  cipherHead: [0xAC, 0x0E, 0xA3, 0x65],   // 样本中 JNI_OnLoad 的密文首 4 字节
  entropyWindow: 0x1000,
  entropyThreshold: 7.0,                  // 加密≈7.7，解密 5.0~6.2
  pollIntervalMs: 20,
  maxWaitModuleMs: 90000,
  maxWaitDecryptMs: 60000,
  dumpAnon: true,
  maxAnonSize: 64 * 1024 * 1024
};

var T0 = Date.now();
function ms() { return Date.now() - T0; }
function log(s) { console.log('[sg +' + (ms() / 1000).toFixed(2) + 's] ' + s); }
function sleep(t) { return new Promise(function (r) { setTimeout(r, t); }); }

/* 跨段/越界安全读取（未映射区域填零，避免整段读取失败） */
function readSafe(addr, size) {
  var out = new Uint8Array(size), off = 0;
  while (off < size) {
    var cur = addr.add(off), chunk = 0x1000, r = null;
    try { r = Process.findRangeByAddress(cur); } catch (e) { r = null; }
    if (r && r.protection.indexOf('r') !== -1) {
      var remain = r.size - cur.sub(r.base).toInt32();
      chunk = Math.min(remain, size - off);
      if (chunk <= 0) chunk = 0x1000;
      try { out.set(new Uint8Array(Memory.readByteArray(cur, chunk)), off); }
      catch (e) { log('read failed @' + cur + ' (' + e + ')'); }
    } else {
      log('unmapped @' + cur + ', fill zeros');
    }
    off += chunk;
  }
  return out;
}

function entropyOf(u8) {
  var hist = new Uint32Array(256);
  for (var i = 0; i < u8.length; i++) hist[u8[i]]++;
  var n = u8.length, h = 0;
  for (var k = 0; k < 256; k++) {
    if (hist[k] > 0) { var p = hist[k] / n; h -= p * Math.log2(p); }
  }
  return h;
}

/* 解密状态判定：首 4 字节不再是密文头 + 熵低于阈值 */
function probeDecrypt(base) {
  var ea = base.add(CFG.jniOnLoadOffset);
  var head = readSafe(ea, 4);
  var win = readSafe(ea, Math.min(CFG.entropyWindow, 0x4000));
  var h = entropyOf(win);
  var sameCipher = head[0] === CFG.cipherHead[0] && head[1] === CFG.cipherHead[1] &&
                   head[2] === CFG.cipherHead[2] && head[3] === CFG.cipherHead[3];
  var plausible = !(head[0] === 0 && head[1] === 0) &&
                  !(head[0] === 0xFF && head[1] === 0xFF && head[2] === 0xFF && head[3] === 0xFF);
  return {
    decrypted: !sameCipher && plausible && h < CFG.entropyThreshold,
    entropy: h,
    head: Array.prototype.map.call(head, function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('')
  };
}

function writeFile(name, u8) {
  var path = CFG.outDir + '/' + name;
  try {
    var f = new File(path, 'wb');
    f.write(u8.buffer); f.flush(); f.close();
    log('saved ' + path + ' (' + u8.length + ' bytes)');
    send({ t: 'file', name: name, path: path, size: u8.length });
    return true;
  } catch (e) {
    log('WRITE FAILED ' + path + ': ' + e);
    send({ t: 'error', msg: 'write failed: ' + e, path: path });
    return false;
  }
}

/* 匿名可执行段（解压产物可能的落点） */
function anonExecRanges(mod) {
  var out = [];
  ['rwx', 'r-x', '--x'].forEach(function (prot) {
    var rs = [];
    try { rs = Process.enumerateRanges(prot); } catch (e) { return; }
    rs.forEach(function (r) {
      if (r.file) return;                                  // 只保留匿名映射
      if (r.size < 0x1000 || r.size > CFG.maxAnonSize) return;
      var overlap = r.base.compare(mod.base) < 0
        ? (r.base.add(r.size).compare(mod.base) > 0)
        : (mod.base.add(mod.size).compare(r.base) > 0);
      if (overlap) return;                                 // 跳过模块自身
      for (var i = 0; i < out.length; i++) if (out[i].base.equals(r.base)) return;
      out.push(r);
    });
  });
  return out;
}

async function waitModule() {
  log('waiting for module ' + CFG.moduleName);
  var deadline = Date.now() + CFG.maxWaitModuleMs;
  while (Date.now() < deadline) {
    var m = Process.findModuleByName(CFG.moduleName);
    if (m) {
      log('module found base=' + m.base + ' size=0x' + m.size.toString(16) + ' path=' + m.path);
      send({ t: 'module', base: m.base.toString(), size: m.size, path: m.path });
      return m;
    }
    await sleep(CFG.pollIntervalMs);
  }
  throw new Error('module not loaded within ' + CFG.maxWaitModuleMs + 'ms');
}

async function waitDecrypt(base) {
  log('waiting decryption (expect entropy ~7.7 at first, then <' + CFG.entropyThreshold + ')');
  var deadline = Date.now() + CFG.maxWaitDecryptMs, lastLog = 0;
  while (Date.now() < deadline) {
    var st = probeDecrypt(base);
    if (Date.now() - lastLog > 1000) {
      lastLog = Date.now();
      log('  probe: head=' + st.head + ' entropy=' + st.entropy.toFixed(2) +
          ' decrypted=' + st.decrypted);
    }
    if (st.decrypted) return st;
    await sleep(100);
  }
  var last = probeDecrypt(base);
  log('DECRYPT TIMEOUT: head=' + last.head + ' entropy=' + last.entropy.toFixed(2));
  return last;
}

async function main() {
  log('start; pid=' + Process.id + ' arch=' + Process.arch);
  var mod = await waitModule();
  var base = mod.base;
  var st = await waitDecrypt(base);

  log('[3/6] dumping fixed segments');
  var written = [];
  for (var i = 0; i < CFG.segs.length; i++) {
    var s = CFG.segs[i];
    if (writeFile(s.name, readSafe(base.add(s.off), s.size))) written.push(s.name);
  }

  if (CFG.dumpAnon) {
    var rs = anonExecRanges(mod);
    log('[4/6] anonymous exec ranges: ' + rs.length);
    for (var j = 0; j < rs.length; j++) {
      var r = rs[j];
      var nm = 'anon_' + r.base.toString().replace(/^0x/, '') + '_' + r.size + '.bin';
      log('  range ' + r.base + ' size=0x' + r.size.toString(16) + ' prot=' + r.protection);
      if (writeFile(nm, readSafe(r.base, r.size))) written.push(nm);
    }
  }

  log('[5/6] files=' + written.length + ' decrypted=' + st.decrypted);
  send({ t: 'done', base: base.toString(), size: mod.size, decrypted: st.decrypted,
         entropy: st.entropy, head: st.head, files: written });
  log('[6/6] DONE');
}

/* 允许驱动重跑 dump，不需要重启进程 */
rpc.exports = {
  redump: function () {
    try {
      var m = Process.findModuleByName(CFG.moduleName);
      if (!m) return 'module not found';
      var st = probeDecrypt(m.base), out = [];
      for (var i = 0; i < CFG.segs.length; i++) {
        var s = CFG.segs[i];
        if (writeFile(s.name, readSafe(m.base.add(s.off), s.size))) out.push(s.name);
      }
      return JSON.stringify({ decrypted: st.decrypted, entropy: st.entropy, files: out });
    } catch (e) { return 'error: ' + e; }
  }
};

main().catch(function (e) {
  log('FATAL: ' + e);
  send({ t: 'fatal', msg: String(e) });
});
```

---

## 附录 C：`sgrun.py`

用途：驱动 `sgdump.js`——准备设备目录、连接远程 `frida-server`、`spawn`/`attach` 目标、等待 `done`、`adb pull` 产物并写 `base.txt`/`meta.json`。
运行：`python sgrun.py --pkg com.xxx --remote 127.0.0.1:27043 --out sg_dump`；或 `python sgrun.py --pkg com.xxx --serial <sn> --attach`。
依赖：Python 3.13（已用 3.13.9 通过 `py_compile`）、`pip install frida`、`adb`、设备端 `frida-server`（默认端口 27043，可用 `adb forward` 转发）。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sgrun.py — 驱动 sgdump.js：spawn 目标、加载脚本、等待 done、adb pull 产物
用法:
  python sgrun.py --pkg com.xxx --remote 127.0.0.1:27043 --out sg_dump
  python sgrun.py --pkg com.xxx --serial <sn> --attach
"""
import argparse, json, os, subprocess, sys, threading
import frida

DEV_DIR = '/data/local/tmp/sgdump'

def sh(cmd, quiet=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0 and not quiet:
        print('[adb][err] %s\n         %s' % (cmd, (r.stderr or r.stdout).strip()))
    return (r.stdout or '').strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pkg', required=True)
    ap.add_argument('--serial', default=None)
    ap.add_argument('--remote', default='127.0.0.1:27043')
    ap.add_argument('--script', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sgdump.js'))
    ap.add_argument('--out', default='sg_dump')
    ap.add_argument('--timeout', type=int, default=150)
    ap.add_argument('--attach', action='store_true', help='attach 到已运行进程，不 spawn')
    args = ap.parse_args()

    adb = 'adb' + (' -s %s' % args.serial if args.serial else '')
    if not os.path.isfile(args.script):
        print('[x] 找不到脚本: %s' % args.script); return 2
    src = open(args.script, 'r', encoding='utf-8').read()
    os.makedirs(args.out, exist_ok=True)

    # frida 的 File API 只能写文件不能建目录，这里先准备好
    sh("%s shell \"sbin/magisk su -c 'rm -rf %s; mkdir -p %s; chmod 777 %s'\"" % (adb, DEV_DIR, DEV_DIR, DEV_DIR))

    host, port = args.remote.split(':')
    sh('%s forward tcp:%s tcp:%s' % (adb, port, port))
    try:
        dev = frida.get_device_manager().add_remote_device(args.remote)
        dev.enumerate_processes()
    except Exception as e:
        print('[x] 连接 frida-server 失败: %s' % e)
        print('    检查: ps -A | grep fs ; adb forward --list ; 端口是否被占用')
        return 3

    if args.attach:
        proc = next((p for p in dev.enumerate_processes() if p.name == args.pkg), None)
        if proc is None:
            print('[x] 未找到运行中的进程 %s' % args.pkg); return 4
        pid = proc.pid
        session = dev.attach(pid)
        print('[+] attached pid=%d' % pid)
    else:
        pid = dev.spawn([args.pkg])
        session = dev.attach(pid)
        print('[+] spawned pid=%d (已挂起，脚本加载后再 resume)' % pid)

    state = {'done': None, 'base': None, 'fatal': None, 'files': []}
    done_evt = threading.Event()

    def on_message(msg, data):
        if msg.get('type') == 'log':
            print(msg['payload']); return
        if msg.get('type') == 'error':
            print('[script error] %s' % msg.get('stack', msg.get('description'))); return
        p = msg.get('payload') or {}
        t = p.get('t')
        if t == 'module':
            state['base'] = p['base']; print('[driver] module base = %s' % p['base'])
        elif t == 'file':
            state['files'].append(p['name'])
        elif t == 'done':
            state['done'] = p; done_evt.set()
        elif t == 'fatal':
            state['fatal'] = p.get('msg'); done_evt.set()
        elif t == 'error':
            print('[driver] script error: %s' % p)

    def on_detached(reason, crash=None):
        print('[!] session detached: reason=%s crash=%s' % (reason, crash))
        if reason == 'process-terminated':
            print('    → 进程已退出：优先怀疑反注入检测，或目标自身崩溃')
        done_evt.set()

    session.on('detached', on_detached)
    script = session.create_script(src)
    script.on('message', on_message)
    script.load()
    if not args.attach:
        dev.resume(pid)
        print('[+] resumed pid=%d' % pid)

    if not done_evt.wait(args.timeout):
        print('[x] 超时 %ds 未拿到 done，现场诊断：' % args.timeout)
        print(sh('%s shell "sbin/magisk su -c \'cat /proc/%d/maps | grep -i vivosg\'"' % (adb, pid)))
        print(sh("%s logcat -d -t 80 | grep -iE 'vivo|sg|frida|DEBUG'" % adb))
        return 5
    if state['fatal']:
        print('[x] 脚本失败: %s' % state['fatal']); return 6

    d = state['done'] or {}
    print('[+] done: base=%s decrypted=%s entropy=%.2f head=%s' %
          (d.get('base'), d.get('decrypted'), d.get('entropy', 0), d.get('head')))

    sh('%s pull %s/. %s' % (adb, DEV_DIR, args.out))
    if state['base']:
        open(os.path.join(args.out, 'base.txt'), 'w').write(state['base'] + '\n')
    json.dump(d, open(os.path.join(args.out, 'meta.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=2)
    print('[+] 产物目录: %s' % os.path.abspath(args.out))
    return 0

if __name__ == '__main__':
    sys.exit(main())
```

---

## 附录 D：`sgverify.py`

用途：校验 dump 产物是否已解密、大小是否正确、A64 prologue 是否合理，并打印匿名段熵。
运行：`python sgverify.py sg_dump`（默认目录 `sg_dump`）；退出码 0=PASS，1=FAIL。
依赖：Python 3.13 标准库（`math/os/struct/sys`），无第三方包。

```python
#!/usr/bin/env python3
import math, os, struct, sys

CIPHER = bytes([0xAC, 0x0E, 0xA3, 0x65])
JNI_OFF = 0x1C33C

def entropy(b):
    if not b: return 0.0
    c = {}
    for x in b: c[x] = c.get(x, 0) + 1
    n = float(len(b))
    return -sum((v / n) * math.log2(v / n) for v in c.values())

d = sys.argv[1] if len(sys.argv) > 1 else 'sg_dump'
p = os.path.join(d, 'seg1_code.bin')
if not os.path.isfile(p):
    print('[x] 缺少 %s' % p); sys.exit(2)

data = open(p, 'rb').read()
win  = data[JNI_OFF:JNI_OFF + 0x1000]
head = data[JNI_OFF:JNI_OFF + 4]
h    = entropy(win)
prologue = head[0] in (0xFD, 0xFF) or (head[1] & 0x03) in (0x01, 0x03)

print('[*] seg1 size=%d (期望 %d)' % (len(data), 0x451E4))
print('    head=%s entropy=%.2f prologue=%s' % (head.hex(), h, prologue))
print('    words=%s' % [hex(w) for w in struct.unpack_from('<8I', data, JNI_OFF)])

ok = head != CIPHER and h < 7.0 and prologue
print('[%s] %s' % ('PASS' if ok else 'FAIL',
                   '可以回填 IDA' if ok else '仍是密文，按第五节排错'))

for name in sorted(os.listdir(d)):
    if name.startswith('anon_') and name.endswith('.bin'):
        b = open(os.path.join(d, name), 'rb').read()
        print('[anon] %-38s size=%-8d entropy=%.2f' % (name, len(b), entropy(b[:0x4000])))
sys.exit(0 if ok else 1)
```

---

## 附录 E：`ida_apply_dump.py`

用途：把 dump 产物回填到 `libvivosgmain.so.i64`——重定基、写入三段、修段权限、重分析、`add_func` 并反编译验证 `JNI_OnLoad`。
运行：IDA 中 `File → Script file…` 选择本脚本；或 `idat -A -S"ida_apply_dump.py" libvivosgmain.so.i64`。
依赖：IDA Pro 9.x + IDAPython（Python 3.13）。已修复 `if` 缺冒号的语法问题，并改用 IDA 9.4 实际存在的 API：`ida_segment.add_segm`（原 `create_segment` 不存在）、`idc.set_segm_attr`（原 `ida_segment.set_segm_attr` 不存在）、权限常量改用 `ida_segment.SEGPERM_*`；已用 Python 3.13.9 `py_compile` 通过。

```python
# -*- coding: utf-8 -*-
from __future__ import print_function

import os

import idaapi
import ida_bytes
import ida_segment
import ida_auto
import ida_funcs
import ida_hexrays
import idc

DUMP_DIR = r'C:\Users\Administrator\Desktop\1\sg_dump'      # 改成你的产物目录

JNI_OFF = 0x1C33C

SEGS = [
    (0x00000, 'seg1_code.bin', 0x451E4, True),
    (0x55B60, 'seg2_data.bin', 0x14078, False),
    (0x6A078, 'seg3_plt.bin',  0x00A5C, True),
]

# 1) 读运行时基址
base_file = os.path.join(DUMP_DIR, 'base.txt')
if not os.path.isfile(base_file):
    print('[x] 缺少 base.txt: %s' % base_file)
else:
    with open(base_file, 'r') as f:
        BASE = int(f.read().strip(), 16)

    print('[+] runtime base = 0x%X' % BASE)

    # 2) 重定基
    cur = idaapi.get_imagebase()
    if cur != BASE:
        ida_segment.rebase_program(BASE - cur, 0)

    if idaapi.get_imagebase() != BASE:
        print('[x] rebase 失败，当前 imagebase = 0x%X' % idaapi.get_imagebase())
    else:
        print('[+] imagebase ok = 0x%X' % idaapi.get_imagebase())

        # 3) 逐段写回
        i = 0
        while i < len(SEGS):
            off = SEGS[i][0]
            fn = SEGS[i][1]
            size = SEGS[i][2]
            is_code = SEGS[i][3]
            i = i + 1

            path = os.path.join(DUMP_DIR, fn)
            if not os.path.isfile(path):
                print('[-] 跳过缺失文件 %s' % fn)
                continue

            with open(path, 'rb') as fh:
                data = fh.read()[:size]

            ea = BASE + off
            seg = ida_segment.getseg(ea)
            if seg is None:
                cls = 'CODE' if is_code else 'DATA'
                ida_segment.add_segm(0, ea, ea + size, 'LOAD', cls)
                seg = ida_segment.getseg(ea)

            ida_bytes.patch_bytes(ea, data)
            print('[+] patched %s -> 0x%X (%d bytes)' % (fn, ea, len(data)))

            # 4) 同段修权限
            if seg is not None:
                if is_code:
                    perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_EXEC
                else:
                    perm = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE
                idc.set_segm_attr(seg.start_ea, idc.SEGATTR_PERM, perm)
                print('[+] %s perm -> %d' % (fn, perm))

        # 5) 重新分析
        ida_bytes.del_items(BASE + JNI_OFF, ida_bytes.DELIT_SIMPLE, 4)
        ida_auto.auto_wait()

        # 6) 验证
        EA = BASE + JNI_OFF
        print('[+] JNI_OnLoad head = %s' % ida_bytes.get_bytes(EA, 16).hex())
        if ida_funcs.add_func(EA, EA + 0x400):
            try:
                code = ida_hexrays.decompile(EA)
                print('[+] pseudocode:')
                print(str(code)[:800])
            except Exception as e:
                print('[-] decompile error: %s' % e)
        else:
            print('[-] add_func 失败，检查段权限是否已改为可执行')
```
