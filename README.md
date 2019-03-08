## changelog（相对于原始开源代码：https://github.com/AndroBugs/AndroBugs_Framework）
2019/2
可作为Django模块。

2018/11/16
1. 拆分文件，提取方法，删除不必要的代码（如存储至数据库）
2. 增加常见壳的检测。检测逻辑：判断是否存在特征.so文件。如360加固：libjiagu.so
3. 增加unzip解压缩（Android平台ZipperDown）漏洞检测（需人工验证是否对..进行校验）。检测逻辑：检测是否调用了java.uti.zip.ZipEntry.getName()
4. 增加"动态注册广播组件暴露风险检测"
5. 增加"APP通用型拒绝服务漏洞检测"
6. 修复"Fragment注入漏洞检测"的bug


## TODO
1. Intent Scheme URL攻击漏洞检测
2. Activity劫持漏洞检测
3. 多dex检测


## 参考
1. [360显微镜安全知识库](http://appscan.360.cn/vulner/list/)
2. [Android应用审计checklist整理](https://github.com/guanchao/AndroidChecklist)
3. [微博国际版 360显微镜检测报告](http://appscan.360.cn/app/7149b94f362001dfa51c783911f4b969/report/)
4. [微博国际版 盘古Janus检测报告](https://www.appscan.io/app-report.html?id=dca2b12201c7d77d630a41f9480f70d4a131fa16)
5. [zANTI 360显微镜检测报告](http://appscan.360.cn/app/b9ce1149e737661710e212c6d0cebe69/report/)
6. [zANTI 盘古Janus检测报告](https://www.appscan.io/app-report.html?id=5fae777a2d8f1134c8555b6826c2db1aa28ddbe7)


## 使用环境
- Python2

## 使用方法
对apk文件进行检测，默认输出到Reports目录。可加`-o`参数指定输出目录
```
python androbugs.py -f [APK file]
```
### 查看帮助
```
python androbugs.py -h
```
## 检测报告
默认在Reports目录下：
- [应用包名]_[唯一标识].txt
- [应用包名]_[唯一标识].txt.json
