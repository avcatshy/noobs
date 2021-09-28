## NetGear  firmware repackage
---

理论上所有网件的固件都可以，这里用R6400v2做示例

步骤：
1. 从网件官网[下载固件](https://www.netgear.com/support/product/R6400v2)以及[GPL开源代码包](https://kb.netgear.com/2649/NETGEAR-Open-Source-Code-for-Programmers-GPL) 
2. binwalk 将固件解包，提取出文件系统squashfs-root，添加工具或修改文件系统，记录文件系统在固件中的偏移
3. 从GPL 包中找到ambitCfg.h（配置文件）， compatible_xxxx.txt（设备信息）以及tools目录下的packet
4. 修改python脚本中mk_firmware的参数
5. 将squashfs-root、ambitCfg.h、compatible_xxxx.txt、packet以及脚本放在一起，执行脚本
6. Enjoy.