<p align="center">
  <img src="resources/icons/logo.png" width="128" alt="HashValue 图标" />
</p>

# HashValue —— 哈希提取工具

把加密文件（zip / 7z / rar / Office / PDF 等）快速转换成 **hashcat 可直接使用**的哈希文件。

## 功能

- 拖拽或选择加密文件，自动识别文件格式并显示对应的 hashcat 模式（如 zip → 17200、7z → 11600、RAR5 → 13000）
- **按类别选择格式**：先选类别（压缩包 / 办公文档 / 密码管理器 / 磁盘加密 / 加密货币 / 密钥证书 / 系统网络等），再选具体格式
- **扫描新格式**：点击“扫描新格式”按钮，自动发现 run 目录里新增的 2john 脚本并加入“新发现”类别（自动记住，重启仍保留）
- 覆盖 50+ 种格式：zip、7z、rar、office、pdf、keepass、1password、bitcoin、luks、dmg、gpg 等
- 提取后**自动去掉文件名前缀**（如 `123.zip:`），保存的 `.txt` 可直接用于：
  ```sh
  hashcat -m <模式号> 哈希.txt 字典.txt
  ```
- **输出后缀可选**：输出文件后缀可在 `.txt / .lst / .hash / 无后缀` 之间选择（自动记住选择）
- 简体中文界面，现代圆角风格
- **独立运行**：已内置 JtR 的 run 目录（zip/rar/Office/PDF 等自带 exe 的格式开箱即用），
  整个文件夹拷到其他电脑即可使用；无需安装

## 依赖

转换依赖 john-packages 解压后 `run` 目录里的 2john 脚本：

👉 **下载 John the Ripper：<https://github.com/openwall/john-packages/releases>**

- 首次使用时在窗口底部设置 JtR 目录（选择解压后含 `john.exe` 和 2john 脚本的 `run` 目录），之后会自动记住；
- 部分格式（`.py` / `.pl` 脚本）需要系统安装 Python 或 Perl 解释器。

## 使用步骤

1. 将加密文件拖入窗口（或点“浏览…”选择）；
2. 确认“文件格式”与右侧的 hashcat 模式号；
3. 点“**提取哈希**”；
4. 复制结果，或直接使用输出的 `.txt` 文件，配合 `hashcat -m <模式号>` 破解。

## 从源码构建

依赖：Qt 5（widgets）、qmake、C++ 编译工具链。

```sh
qmake
make
```

## 许可证

BSD 2-Clause。
