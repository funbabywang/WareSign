# 关于
WareSign 数字签名工具
Copyright:© Deep Learning Corporation. All rights reserved.
# 用法
WareSign sign file:C:\temp\main.exe cert:C:\temp\cert.pfx /password mypass
                  签名的文件路径          证书路径（pfx）              密码
如果一切没有错误，比如您的证书是C:\temp\cert.pfx，签名文件是C:\temp\main.exe您将会看到：
WareSign:Sign File:C:\temp\main.exe
Cert:C:\temp\cert.pfx
Sign Success
错误则报出错误原因
# 依赖
Microsoft Windows、Omege UOS 环境
安装了 Microsoft.NET 8.0
系统内有 System.Security.Cryptography.Pkcs.dll
安装的 WareSign 文件夹一个 runtimes（运行时库）
