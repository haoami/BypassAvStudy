# BypassAvStudy
rust 免杀记录学习

## BypassAv_demo1
实现如下
- BypassAv_demo1:
  uuid加载shellcode
- BypassAv_demo1_2：
  基础shellcode 执行
- BypassAv_demo1_3：
  shellcode静态混淆加密 + 导入表混淆 + 禁用 Windows 事件跟踪，ETW禁用杀软检测的比较频繁，最好不加

过360 火绒
![](https://github.com/haoami/BypassAvStudy/blob/a86bc31ebeb671d32464f5955f2ab0b607e0e3eb/png/1.png)

vt检测出来了3个，加ETW禁用vt检测12个。。
![](https://github.com/haoami/BypassAvStudy/blob/a86bc31ebeb671d32464f5955f2ab0b607e0e3eb/png/2.png)

## BypassAv_demo2

- BypassAv_demo2：
  简单syscall示例，远程线程注入 
- BypassAv_demo2_1:
  syscall + apc注入
  
 windows defender，卡巴，360，火绒运行时能成功上线，但后续的cs指令由于cs带有特征所以卡巴会检测出来。
![](http://39.107.239.30:3000/uploads/0173f9c0-8737-4ac0-bb07-d3c8c9becacf.png)
![](http://39.107.239.30:3000/uploads/d55bffc8-a68a-436e-b3a0-f7d23cecdab5.png)
成功上线
![](http://39.107.239.30:3000/uploads/f853a30b-eeae-47d3-9d54-8adb3ccaf62b.png)
