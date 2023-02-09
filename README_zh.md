# autoRebind 

[README](README.md) | [中文文档](README_zh.md)

autoRebind可以解析CobaltStrike的`Malleable C2 profile`，转换成[CrossC2](https://github.com/gloxec/CrossC2)可用的通信库源码


## Usage

`autoRebind <c2profile> [section-name] > rebind.c`

默认读取c2profile文件中的default section配置


当c2profile中存在多个 http-get/post 节时，可以指定节名称来做解析


## Note

`gcc -fPIC -shared rebind.c -o librebind.so`

生成的`rebind.c`源文件尽量在低版本Linux系统下进行编译，否则可能会因为目标系统上`GLIBC版本过高`不兼容


