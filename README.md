# BypassAvStudy
rust 免杀记录学习

## BypassAv_demo1
实现如下
- uuid加载shellcode  (BypassAv_demo1)
- 基础shellcode 执行 (BypassAv_demo1_2)
- shellcode静态混淆加密 + 导入表混淆 + 禁用 Windows 事件跟踪(BypassAv_demo1_3)，ETW禁用杀软检测的比较频繁，最好不加
过360 火绒
![](https://github.com/haoami/BypassAvStudy/blob/a86bc31ebeb671d32464f5955f2ab0b607e0e3eb/png/1.png)

vt检测出来了3个，加ETW禁用vt检测12个。。
![](https://github.com/haoami/BypassAvStudy/blob/a86bc31ebeb671d32464f5955f2ab0b607e0e3eb/png/2.png)



