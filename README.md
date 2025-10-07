# Naver Series Extractor
### TOOLS NEEDED TO USE THE SCRIPT

- Install Python with pip (recommended version 3.10 or 3.11).
- 使用 pip 安装 Python (推荐版本 3.10 或 3.11)。

- Install ADB, either with NexusTools or a similar tool (you can search for it on Google).
- 安装 ADB，可以使用 NexusTools 或类似的工具（你可以在 Google 上搜索它）。

- Have a rooted Android phone or use an emulator (it's best to have a rooted phone; although the app detects root access, you can download the chapters first, then install the root binary, uninstall the root access afterward, and that's it). This script does not require the app to be open.
- 拥有一部已 Root 的安卓手机或使用模拟器（最好是已 Root 的手机；尽管应用会检测 Root 权限，但你可以先下载章节，然后安装 Root 二进制文件，之后再卸载 Root 权限即可）。此脚本不需要应用程序保持打开状态。

- Finally, and most importantly, download the ZIP file, extract it, and install the requirements using:
- 最后，也是最重要的，下载 ZIP 文件，解压，并使用以下命令安装所需依赖：
```
pip install -r requirements.txt
```

### TO USE THE SCRIPT:

Run the command:
python series.py
```
options:
  -h, --help       show this help message and exit
  --output OUTPUT  Output directory (default: out)
  --run-with-sudo  Run adb commands with sudo (default: False)
  --host HOST      ADB host (default: 127.0.0.1)
  --port PORT      ADB port (default: 5037)
```
