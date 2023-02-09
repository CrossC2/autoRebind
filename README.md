# autoRebind 

[README](README.md) | [中文文档](README_zh.md)

autoRebind can parse CobaltStrike's `Malleable C2 profile` and convert it into the source code of the communication library available to [CrossC2](https://github.com/gloxec/CrossC2)

## Usage

`autoRebind <c2profile> [section-name] > rebind.c`



Read the `default section` configuration in the c2profile file by default



When there are multiple `http-get/post` sections in c2profile, you can specify the section name for parsing

## Note

`gcc -fPIC -shared rebind.c -o librebind.so`



The generated `rebind.c` source file should be compiled under a low-version Linux system as much as possible, otherwise it may be incompatible due to the `GLIBC version is too high` on the target system

