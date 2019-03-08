#coding=utf-8

#Fix settings:
TYPE_REPORT_OUTPUT_ONLY_PRINT = "print"                #报告只输出到终端
TYPE_REPORT_OUTPUT_ONLY_FILE = "file"                  #报告写入.txt文件
TYPE_REPORT_OUTPUT_PRINT_AND_FILE = "print_and_file"   #都

TYPE_COMPARE_ALL = 1
TYPE_COMPARE_ANY = 2

ANALYZE_MODE_SINGLE = "single"
ANALYZE_MODE_MASSIVE = "massive"

#AndroidManifest permission protectionLevel constants
PROTECTION_NORMAL = 0   # "normal" or not set
PROTECTION_DANGEROUS = 1
PROTECTION_SIGNATURE = 2
PROTECTION_SIGNATURE_OR_SYSTEM = 3
PROTECTION_MASK_BASE = 15
PROTECTION_FLAG_SYSTEM = 16
PROTECTION_FLAG_DEVELOPMENT = 32
PROTECTION_MASK_FLAGS = 240

LEVEL_HIGH =   "高危"
LEVEL_MEDIUM = "中危"
LEVEL_LOW =    "低危"
LEVEL_INFO =   "提示"

# 根据Windows/Linux平台不同设置输出时一行最大的字符数
LINE_MAX_OUTPUT_CHARACTERS_WINDOWS = 16000  #100
LINE_MAX_OUTPUT_CHARACTERS_LINUX = 16000
LINE_MAX_OUTPUT_INDENT = 20    # 缩进量

# 自定义设置
DEBUG = True
ANALYZE_ENGINE_BUILD_DEFAULT = 1    # Analyze Engine(use only number)


#这里将默认的方式设置为终端和文件都输出
REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE  #when compiling to Windows executable, switch to "TYPE_REPORT_OUTPUT_ONLY_FILE"
DIRECTORY_REPORT_OUTPUT = "Reports/"	#Only need to specify when (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_ONLY_FILE) or (REPORT_OUTPUT = TYPE_REPORT_OUTPUT_PRINT_AND_FILE)
# DIRECTORY_REPORT_OUTPUT = "Massive_Reports/"


# 不希望检测的包名（比如一些第三方SDK，可以先认为没有问题），两个包名之间用“|”隔开
LIST_EXCLUDE_CLASSES = ["Landroid/", "Lcom/android/", "Lcom/actionbarsherlock/",
                        "Lorg/apache/", "Lcom/google/", "Lcom/faceboo/","Lcom/umeng/",
                        "Lcom/alipay/", "Lcom/baidu/", "Lcom/tencent/mm/sdk/"]

STR_LIST_EXCLUDE_CLASSES = "^(Landroid/support/|Lcom/actionbarsherlock/|Lorg/apache/|Lcom/google|Lcom/facebook|Lcom/umeng|Lcom/alipay)"

EXCEPTION_URL_STRING = [
    "http://example.com",
    "http://example.com/",
    "http://www.example.com",
    "http://www.example.com/",
    "http://www.google-analytics.com/collect",
    "http://www.google-analytics.com",
    "http://hostname/?",
    "http://hostname/"]

ENABLE_EXCLUDE_CLASSES = True

#TODO Provider 路径穿越漏洞检测

"""
tag: 漏洞项的唯一标识；
name: 漏洞检测项的名字；
level：漏洞危害级别（高危、中危、低危、提示）；
desc：对该漏洞的简单介绍；
detail：针对特定app检测出来该漏洞的具体情况（比如产生漏洞的代码，或者url）；
fix：对该漏洞的修复建议，一般会有与该漏洞相关的案例。
"""
VUL_SSL_URLS_NOT_IN_HTTPS = {
    'tag': "SSL_URLS_NOT_IN_HTTPS",
    'name': "非HTTPs的URL检测",
    'level': LEVEL_INFO,
    'desc': "URL没有使用SSL安全协议",
    'detail': "",
    'fix': "如果使用http协议加载url，应进行白名单过滤、完整性校验等防止访问的页面被篡改。"
}
VUL_SSL_X509 = {
    'tag': "SSL_X509",
    'name': "SSL证书弱校验漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "App在实现X509TrustManager时，覆盖google的证书检查机制X509TrustManager方法：checkClientTrusted、checkServerTrusted和getAcceptedIssuers之后，检查证书是否合法的责任，就落到了我们自己的代码上。而此处却没有对证书进行应有的安全性检查，直接接受了所有异常的https证书，不提醒用户存在安全风险，也不终止这次危险的连接，会导致中间人攻击漏洞。",
    'detail': "",
    'fix': "如果自己创建X509Certificate，则在覆盖”checkClientTrusted”、“checkServerTrusted”和“getAcceptedIssuers”后要进行校验。 参考：1. [Android证书信任问题与大表哥](http://www.vuln.cn/6060); 2. [窃听风暴： Android平台https嗅探劫持漏洞](http://www.vuln.cn/7032)"
}
VUL_SSL_CN1 = {
    'tag': "SSL_CN1",
    'name': "SSL主机名弱校验漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "自定义HostnameVerifier类, 却不实现verify方法验证域名, 导致中间人攻击",
    'detail': "",
    'fix': "自定义HostnameVerifier类并实现verify方法验证域名。参考：[国内绝大部分Android APP存在信任所有证书漏洞](http://wooyun.jozxing.cc/static/bugs/wooyun-2014-079358.html)"
}
VUL_SSL_CN2 = {
    'tag': "SSL_CN2",
    'name': "SSL关闭主机名验证检测",
    'level': LEVEL_MEDIUM,
    'desc': "App调用setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)，或空的HostnameVerifier。信任所有主机名，会导致中间人攻击。",
    'detail': "",
    'fix': "严格校验SSL证书。参考：http://wooyun.jozxing.cc/static/bugs/wooyun-2014-079358.html http://wooyun.jozxing.cc/static/bugs/wooyun-2016-0190773.html"
}
VUL_SSL_CN3 ={
    'tag': "SSL_CN3",
    'name': "SSL不安全组件检测",
    'level': LEVEL_LOW,
    'desc': "SSLCertificateSocketFactory#getInsecure方法无法执行SSL验证检查，使得网络通信遭受中间人攻击。",
    'detail': "",
    'fix': "移除SSLCertificateSocketFactory#getInsecure方法。参考：https://developer.android.com/reference/android/net/SSLCertificateSocketFactory#getInsecure(int,%20android.net.SSLSessionCache)"
}
VUL_SSL_DEFAULT_SCHEME_NAME = {
    'tag': "SSL_DEFAULT_SCHEME_NAME",
    'name': "HttpHost检测",
    'level': LEVEL_LOW,
    'desc': "HttpHost.DEFAULT_SCHEME_NAME默认是http，不安全。",
    'detail': "",
    'fix': "改成使用HTTPs。"
}
VUL_SSL_WEBVIEW = {
    'tag': "SSL_WEBVIEW",
    'name': "WebView忽略SSL证书错误漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "Android WebView组件加载网页发生证书认证错误时，会调用WebViewClient类的onReceivedSslError方法，在onReceivedSslError()中使用 proceed()方法表示当证书效验错误时忽略错误继续传输，则会受到中间人攻击的威胁，可能导致隐私泄露。",
    'detail': "",
    'fix': "当发生证书认证错误时，采用默认的处理方法handler.cancel()，停止加载问题页面。 参考：http://wooyun.jozxing.cc/static/bugs/wooyun-2015-0109266.html"
}
VUL_WEBVIEW_JS_ENABLED = {
    'tag': "WEBVIEW_JS_ENABLED",
    'name': "WebView潜在XSS漏洞检测",
    'level': LEVEL_LOW,
    'desc': "WebView允许执行JavaScript(setJavaScriptEnabled(true))，可能导致XSS攻击。",
    'detail': "",
    'fix': """应尽量避免使用WebView执行JavaScript。如果一定要使用：
1、API >= 17的Android系统。出于安全考虑，为了防止Java层的函数被随意调用，Google在4.2版本之后，规定允许被调用的函数必须以@JavascriptInterface进行注解。
2、API < 17的Android系统。建议不要使用addJavascriptInterface接口，以免带来不必要的安全隐患，如果一定要使用该接口：
1)如果使用https协议加载url，应用进行证书校验防止访问的页面被篡改挂马
2)如果使用http协议加载url，应进行白名单过滤、完整性校验等防止访问的页面被篡改
3)如果加载本地html，应将html文件内置在apk中，以及进行对html页面完整性的校验
3、使用removeJavascriptInterface移除Android系统内部的默认内置接口：searchBoxJavaBridge_、accessibility、accessibilityTraversal 参考：http://01hackcode.com/wiki/8.2"""
}
VUL_WEBVIEW_RCE = {
    'tag': "WEBVIEW_RCE",
    'name': "WebView远程代码执行漏洞检测",
    'level': LEVEL_HIGH,
    'desc': "Android API < 17之前版本存在远程代码执行漏洞，该漏洞源于程序没有正确限制使用addJavaScriptInterface方法，当Android 4.2以下版本用户打开恶意链接时（或结合中间人攻击注入恶意js代码），攻击者可以通过Java反射利用该漏洞执行任意Java对象的方法，导致远程代码执行漏洞。漏洞POC演示：https://asecuritysite.com/subjects/chapter46 案例参考：[唱吧android app中存在webview远程执行漏洞](https://wy.tuisec.win/wooyun-2015-0140708.html)",
    'detail': "",
    'fix': "API >= 17的Android系统，为防止Java层函数被随意调用，不要使用addJavascriptInterface方法。在Android 4.0-4.3.1版本中，如果调用了webkit引擎系统会默认添加一个叫searchBoxJavaBridge_的接口，同样会造成远程代码执行，应调用removeJavascriptInterface方法删除searchBoxJavaBridge_接口。参考：http://wooyun.jozxing.cc/static/drops/papers-548.html"
}
VUL_WEBVIEW_ALLOW_FILE_ACCESS = {
    'tag': "WEBVIEW_ALLOW_FILE_ACCESS",
    'name': "WebView File域同源策略绕过漏洞检测",
    'level': LEVEL_HIGH,
    'desc': "系统版本API Level小于15时，系统WebView组件存在通用型的同源策略绕过漏洞。应用程序一旦使用WebView并支持File域，就会受到该漏洞的攻击。恶意应用通过该漏洞，可在无特殊权限下盗取应用的任意私有文件，尤其是浏览器，可通过利用该漏洞，获取到浏览器所保存的密码、Cookie、收藏夹以及历史记录等敏感信息，从而造成敏感信息泄露 。",
    'detail': "",
    'fix': "1. 将不必要导出的组件设置为不导出。2. 如果需要导出组件，禁止使用File域：myWebView.getSettings.setAllowFileAccess(false); 3. 如果需要使用File协议，则设置禁止File协议调用JavaScript：myWebView.getSettings.setJavaScriptEnabled(false); 参考：http://01hackcode.com/wiki/8.3"
}
VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE = {
    'tag': "MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE",
    'name': "数据库/配置/文件全局读写漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "1、APP在使用openOrCreateDatabase创建数据库时，2、使用getSharedPreferences()访问配置文件，3、使用getDir()和openFileOutput()访问文件/目录时，将第二个参数设置为Context.MODE_WORLD_READABLE(1)/Context.MODE_WORLD_WRITEABLE(2)或其值之和3，将数据库/文件/目录设置了全局的可读/可写权限，攻击者恶意读取数据库/文件内容，获取敏感信息。",
    'detail': "",
    'fix': "1、用MODE_PRIVATE模式创建数据库/文件; 使用SQLCipher等工具加密数据库; 避免在数据库中存储明文和敏感信息。2、调用getSharedPrefernces()的时候，设置参数为MODE_PRIVATE(0)或MODE_APPEND(32768)。参考：1、https://blog.csdn.net/u013107656/article/details/51839273； 2、https://developer.android.com/reference/android/content/Context#MODE_WORLD_READABLE。3、手动检测文件内容，避免在文件中存储明文敏感信息。"
}
VUL_PERMISSION_DANGEROUS = {
    'tag': "PERMISSION_DANGEROUS",
    'name': "AndroidManifest危险ProtectionLevel权限检测",
    'level': LEVEL_INFO,
    'desc': "由于对app的自定义permission的protectionLevel属性设置不当，会导致组件（如：Content Provider）数据泄露危险。",
    'detail': "",
    'fix': "最好的权限设置应为“signature”或“signatureOrSystem”，避免被第三方应用利用。"
}
VUL_PERMISSION_EXPORTED = {
    'tag': "PERMISSION_EXPORTED",
    'name': "AndroidManifest组件暴露检测",
    'level': LEVEL_LOW,
    'desc': "Activity、activity-alias、service、receiver组件对外暴露会导致数据泄露和恶意DoS攻击。在AndroidManifest.xml文件中如果应用的组件android:exported属性显式指定为“true”，或者虽然没有显式指定为“true”或“false”，但是有intent-filter并指定了相应的Action，则此组件为导出的组件。（为确认实际风险，建议人工手动确认）。漏洞详情参考：http://01hackcode.com/wiki/7.1",
    'detail': "",
    'fix': "1. 在不影响业务的情况下，最小化组件暴露，对不会参与跨应用调用的组件添加android:exported=”false”属性。2.设置组件访问权限。对跨应用间调用的组件或者公开的receiver、service、activity和activity-alias将权限设置为”signature”或”signatureOrSystem”3、如果该组件因为各种原因，需要导出，那么请检查该组件能不能根据该组件的intent去启动其他私有组件。如果能，请根据业务严格控制过滤和校验intent中的内容，同时被启动的私有组件需要做好各种安全防范。参考：https://zhuanlan.zhihu.com/p/26206339"
}
VUL_PERMISSION_NO_PREFIX_EXPORTED = {
    'tag': "PERMISSION_NO_PREFIX_EXPORTED",
    'name': "AndroidManifest Exported Lost Prefix Checking",
    'level': LEVEL_LOW,
    'desc': "Found exported components that forgot to add \"android:\" prefix (AndroidManifest.xml). ",
    'detail': "",
    'fix': "AndroidManifest.xml响应标签中加上属性android:exported=”false”"
}
VUL_PERMISSION_PROVIDER_EXPORTED = {
    'tag': "PERMISSION_PROVIDER_EXPORTED",
    'name': "AndroidManifest Content Provider暴露检测",
    'level': LEVEL_LOW,
    'desc': "provider组件导出可能会带来信息泄露隐患。未显式设置exported=“false”，存在安全风险。由于该属性在API 17才引入，android:targetSdkVersion < 17的所有应用的android:exported属性默认值为true, android:targetSdkVersion >= 17默认值为false。参考：https://developer.android.com/guide/topics/manifest/provider-element",
    'detail': "",
    'fix': "1. 在不影响业务的情况下，最小化组件暴露，对不会参与跨应用调用的组件添加android:exported=”false”属性。2.设置组件访问权限。对导出的provider组件设置权限，同时将权限的protectionLevel设置为”signature”或”signatureOrSystem”。参考：http://01hackcode.com/wiki/7.2"
}
VUL_ALLOW_BACKUP ={
    'tag': "ALLOW_BACKUP",
    'name': "AndroidManifest allowBackup标志检测",
    'level': LEVEL_LOW,
    'desc': "android:allowBackup=\"true\"表示应用允许用户通过系统备份工具备份应用数据然后恢复,目前大部分涉及用户隐私与财产安全的应用都不会选择开启此功能,因为这样用户在未root的情况下应用数据短时间内被攻击者复制。",
    'detail': "",
    'fix': "设置AndroidManifest.xml的android:allowBackup标志为false。参考：http://www.droidsec.cn/android%E5%B1%9E%E6%80%A7allowbackup%E5%AE%89%E5%85%A8%E9%A3%8E%E9%99%A9%E6%B5%85%E6%9E%90/"
}
VUL_DEBUGGABLE ={
    'tag': "DEBUGGABLE",
    'name': "AndroidManifest文件debuggable配置检测",
    'level': LEVEL_HIGH,
    'desc': "在AndroidManifest.xml中定义debuggable项，如果该项被打开(默认打开)，app存在被恶意程序调试的风险，可能导致泄露敏感信息等问题。",
    'detail': "",
    'fix': "显式设置AndroidManifest.xml的debuggable标志为false。"
}
VUL_FRAGMENT_INJECTION ={
    'tag': "FRAGMENT_INJECTION",
    'name': "Fragment注入漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "在API < 19的(Android 4.4)的app，所有继承了PreferenceActivity类的Activity, 并将该类设置为exported的应用都受到Fragment注入漏洞的威胁。该漏洞可导致拒绝服务。由于通过该漏洞可以加载app里面的任何类，包括未导出类，如果未导出类对畸形消息处理不当，将会导致本地拒绝服务漏洞。参考漏洞作者的分析：https://securityintelligence.com/new-vulnerability-android-framework-fragment-injection/",
    'detail': "",
    'fix': "当Android api >=19时，要重写每一个PreferenceActivity类下的isValidFragment方法以避免异常抛出；当Android api < 19时，如果在PreferenceActivity内没有引用任何fragment，建议重写isValidFragment并返回false。参考：[Fragment Injection漏洞杂谈](http://drops.xmd5.com/static/drops/mobile-8165.html) [Fragment 注入](http://appscan.360.cn/vulner/list/) [邮件列表](https://seclists.org/fulldisclosure/2013/Dec/55)"
}
VUL_GENERAL_DOS ={
    'tag': "GENERAL_DOS",
    'name': "APP通用型拒绝服务漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "Android应用本地拒绝服务漏洞源于导出组件没有对Intent.getXXXExtra()获取的异常或者畸形数据进行异常捕获，从而导致攻击者可通过向受害者应用发送此类空数据、异常或者畸形数据来达到使该应用crash的目的（暂未实现try/catch检测逻辑，需手动查看代码验证）。漏洞POC参考：[Android应用本地拒绝服务漏洞浅析](http://www.droidsec.cn/android%E5%BA%94%E7%94%A8%E6%9C%AC%E5%9C%B0%E6%8B%92%E7%BB%9D%E6%9C%8D%E5%8A%A1%E6%BC%8F%E6%B4%9E%E6%B5%85%E6%9E%90/)。漏洞危害：当应用被恶意应用攻击时，本地拒绝服务一般会导致正在运行的应用崩溃，首先影响用户体验，其次影响到后台的Crash统计数据，另外比较严重的后果是应用如果是系统级的软件，可能导致手机重启。Nexus 5曾经出现过这样的情况，它预装了一个用来测试网络连通性的系统应用，这个应用是隐藏状态，无法在桌面上打开，包名为com.lge.SprintHiddenMenu。在Android 4.4.3之前的版本里，这个应用里有大量导出的activity，这些 activity不需要任何权限就可以被外部调用。其中一个为com.lge.SprintHiddenMenu.sprintspec.SCRTN的组件是导出的，并且没有任何权限限制，给它发送一个空Intent，可导致Nexus 5手机重启。来源：https://segmentfault.com/a/1190000007262686",
    'detail': "",
    'fix': "1、防止引起拒绝服务，尤其是杀毒、安全防护、锁屏防盗等安全应用，在AndroidMenifest.xml文件中，将相应组件的“android:exported”属性设置为“false。这样就算这个组件有问题，攻击者也没有办法从外部启动这个组件，就不会执行到有问题的代码。2、在调用getParcelableExtra()、getParcelable()、getSerializableExtra()、getSerializable()方法的地方添加try/catch异常捕获（空指针异常、类型转换异常、数组越界访问异常、类未定义异常、其他异常）。 参考：[应用本地拒绝服务漏洞检测](http://01hackcode.com/wiki/7.8)"
}
#TODO
VUL_ACTIVITY_HIJACKING ={
    'tag': "ACTIVITY_HIJACKING",
    'name': "Activity劫持漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "界面劫持通俗来说就是病毒或木马在后台实时监控某个窗口的产生，例如QQ、支付宝、手机银行等软件的登录界面。一旦发现目标窗口出现，病毒就马上创建一个跟目标窗口一毛一样的窗体来覆盖在它之上。来源：https://segmentfault.com/a/1190000004439893当发生界面劫持时，用户在无察觉的情况下将自己的账号、密码信息输入到仿冒界面中，恶意程序再把这些数据上报到其自身服务器，这个过程便是钓鱼攻击。原理：由于Android的设计缺陷,当我们为某Activity指定标志位FLAG_ACTIVITY_NEW_TASK时,就能使Activity置于栈顶,并呈现给用户。启动Activity的消息可被第三方应用劫持，第三方应用可以启动钓鱼界面来欺骗用户。",
    'detail': "",
    'fix': "在关键Activity(如在登录窗口等需要用户输入敏感信息处)的onPause方法中检测最前端Activity应用是不是自身或者是系统应用。参考：https://segmentfault.com/a/1190000004967637"
}
VUL_WEBVIEW_CLEAR_PASSWORD ={
    'tag': "WEBVIEW_CLEAR_PASSWORD",
    'name': "WebView密码明文存储漏洞检测",
    'level': LEVEL_LOW,
    'desc': "该app的WebView组件未设置关闭自动保存密码功能。Android的WebView组件默认打开了提示用户是否保存密码的功能，若用户选择保存，用户名和密码将被明文存储到该/data/data/[应用名]/databases/webview.db文件中。其他恶意程序可能通过漏洞访问该应用的WebView数据库，导致用户密码泄露。",
    'detail': "",
    'fix': "对WebView显式设置WebView.getSettings().setSavePassword(false)，以禁止保存密码。参考：1）http://01hackcode.com/wiki/8.4 2)[Android中webview缓存密码带来的问题](https://www.claudxiao.net/2013/03/android-webview-cache/) 3）https://developer.android.com/reference/android/webkit/WebSettings.html#setSavePassword(boolean)"
}
VUL_DYNAMIC_BROADCAST ={
    'tag': "DYNAMIC_BROADCAST",
    'name': "动态注册广播组件暴露风险检测",
    'level': LEVEL_LOW,
    'desc': "BroadcastReceiver组件一般分为两种，一种是静态注册，提前在AndroidManifest.xml声明组件；另外一种是动态注册，在代码中使用registerReceiver()方法注册BroadcastReceiver，只有当registerReceiver()的代码执行到了才进行注册。很多开发者没有意识到，如上使用registerReceiver()方法注册的是全局BroadcastReceiver，和静态注册BroadcastReceiver android:exported属性为true性质一样，如果没有指定权限访问控制（permission参数），可以被任意外部应用访问，向其传递Intent，根据具体情况产生的危害可能不同，一种比较普遍的情况是容易产生本地拒绝服务漏洞。来源：https://segmentfault.com/a/1190000007262686。使用普通带两个参数的registerReceiver()方法动态注册的广播在组件的生命周期里是默认导出的。导出的广播可以导致拒绝服务、数据泄漏或是越权调用。",
    'detail': "",
    'fix': "对于动态注册的BroadcastReceiver，尽量少用registerReceiver()方法，如果只在本应用内通信，改用更高效安全的API，如LocalBroadcastManager的registerReceiver()进行本地注册，如果必须导出给外部应用，在使用registerReceiver()时要指定好相应的访问权限。与普通的Broadcast相比，LocalBroadcast不需要发送全局广播，效率更高，而且发送的数据不能被其他应用接收，其他应用也不能发送这些广播到我们的app。参考：https://blog.csdn.net/u010687392/article/details/49744579 https://developer.android.com/reference/android/support/v4/content/LocalBroadcastManager 2、使用带权限校验的含四个参数的registerReceiver(myReceiver,myIntentFilter,myPermission,...),设置myPermission权限属性为system或systemOrSignature级别。参考：https://developer.android.com/reference/android/content/Context.html#registerReceiver(android.content.BroadcastReceiver,%20android.content.IntentFilter,%20java.lang.String,%20android.os.Handler)"
}
VUL_LOG_DISCLOSURE ={
    'tag': "LOG_DISCLOSURE",
    'name': "日志泄露风险检测",
    'level': LEVEL_LOW,
    'desc': "该漏洞危害程度取决于log泄露信息的敏感程度。在APP的开发过程中，为了方便调试，通常会使用log函数输出一些关键流程的信息，这些信息中通常会包含敏感内容，如执行流程、明文的用户名密码等，这会让攻击者更加容易的了解APP内部结构方便破解和攻击，甚至直接获取到有价值的敏感信息。",
    'detail': "",
    'fix': "移除相关的Log方法。 参考：http://wooyun.jozxing.cc/static/bugs/wooyun-2014-082717.html"
}
#TODO  需结合动态检测？
VUL_INTENT_SCHEME_URL ={
    'tag': "INTENT_SCHEME_URL",
    'name': "Intent Scheme URL攻击漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "该漏洞可导致cookie劫持和UXSS漏洞。Intent Scheme URL是一种特殊的URL格式，若浏览器支持Intent scheme URL（大多数主流浏览器都支持此功能），在其访问特殊构造的页面时，会根据页面中声明的Intent调用攻击者想要启动的Activity。原理参考：[Intent scheme URL attack](http://www.vuln.cn/6266) 案例参考：[qq浏览器IntentScheme处理不当](http://wooyun.jozxing.cc/static/bugs/wooyun-2014-073875.html)",
    'detail': "",
    'fix': "1、使用网页传过来的Intent时，要进行过滤和检查。具体修复代码见：[Android Intent Scheme URLs攻击](https://blog.csdn.net/l173864930/article/details/36951805)"
}
#需结合工具人工检测
VUL_ZIPPERDOWN ={
    'tag': "ZIPPERDOWN",
    'name': "unzip解压缩（ZipperDown）漏洞检测",
    'level': LEVEL_MEDIUM,
    'desc': "[*请手动验证是否存在该漏洞！]该漏洞最常见的场景是从服务器下载压缩包，进行资源、代码热更新的时候。Java代码在解压ZIP文件时会使用到ZipEntry类的getName()方法。如果ZIP文件中包含“../”的字符串，该方法返回值里面会原样返回。如果在这里没有进行防护，继续解压缩操作，就会将解压文件创建到其他目录中，实现路径穿越。攻击者可构造恶意zip文件，包含恶意.so文件，被解压的文件将会进行目录跳转被解压到其他目录，覆盖相应文件导致任意代码执行。ZipperDown的本质实际上是路径问题, 利用../来访问任意目录达到写入恶意文件的目的。考虑到需要一定的攻击场景（攻击者需要与受害者处于同一局域网下, 并且劫持通信），评为中危：参考：https://www.tr0y.wang/2018/05/15/zipperdown/index.html ",
    'detail': "",
    'fix': "1、开发中在使用第三方解压库对Zip文件解压过程中，要对Zip内部文件名进行“../”过滤（if entry.getName().contains.(“../”){Log.i(TAG, “解压存在路径穿越漏洞”)}）；2、严格使用https下载Zip文件，或者对下载的Zip文件进行安全校验防止篡改，避免处理不可信Zip文件。 参考：[Android安全开发之ZIP文件目录遍历](http://wooyun.jozxing.cc/static/drops/mobile-17081.html)"
}
VUL_DYNAMIC_CODE_LOADING ={
    'tag': "DYNAMIC_CODE_LOADING",
    'name': "外部动态加载DEX文件检测",
    'level': LEVEL_HIGH,
    'desc': "[*请手动验证加载的dex/jar文件是否在外部目录！]动态加载的DEX文件存储在被其他应用任意读写的目录中(如sdcard)，如果没有对外部所加载的DEX文件做完整性校验，应用将会被恶意代码注入，从而执行的是恶意代码。 案例参考：[QQ游戏Android客户端漏洞导致任意代码执行和密码泄漏](https://bugs.shuimugan.com/bug/view?bug_no=9299)",
    'detail': "",
    'fix': "1. 将所需要动态加载的DEX/APK文件放置在APK内部或应用私有目录中;2. 使用加密网络协议进行下载加载的DEX/APK文件并将其放置在应用私有目录中;3. 对不可信的加载来源进行完整性校验。 参考：[外部动态加载DEX安全风险浅析](http://www.droidsec.cn/%E5%A4%96%E9%83%A8%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BDdex%E5%AE%89%E5%85%A8%E9%A3%8E%E9%99%A9%E6%B5%85%E6%9E%90/)"
}
VUL_EXTERNAL_STORAGE ={
    'tag': "EXTERNAL_STORAGE_ACCESS",
    'name': "外部存储设备访问风险检测",
    'level': LEVEL_HIGH,
    'desc': "文件存放在external storage，例如SD卡，是全局可读写的。由于external storage可以被任何用户操作，且可以被所有的应用修改使用。所以，app的敏感数据建议不要存放在external storage。",
    'detail': "",
    'fix': "app的敏感数据建议不要存放在外部存储设备。"
}
# 参考：https://github.com/zsdlove/ApkVulCheck/blob/master/plugin/shellDetector.py
PACKER_FEATURES={
    "libchaosvmp.so":"娜迦",
    "libddog.so":"娜迦",
    "libfdog.so":"娜迦",
    "libedog.so":"娜迦企业版",
    "libexec.so":"爱加密",
    "libexecmain.so":"爱加密",
    "ijiami.dat":"爱加密",
    "ijiami.ajm":"爱加密企业版",
    "libsecexe.so":"梆梆免费版",
    "libsecmain.so":"梆梆免费版",
    "libSecShell.so":"梆梆免费版",
    "libDexHelper.so":"梆梆企业版",
    "libDexHelper-x86.so":"梆梆企业版",
    "libprotectClass.so":"360",
    "libjiagu.so":"360",
    "libjiagu_art.so":"360",
    "libjiagu_x86.so":"360",
    "libegis.so":"通付盾",
    "libNSaferOnly.so":"通付盾",
    "libnqshield.so":"网秦",
    "libbaiduprotect.so":"百度",
    "aliprotect.dat":"阿里聚安全",
    "libsgmain.so":"阿里聚安全",
    "libsgsecuritybody.so":"阿里聚安全",
    "libmobisec.so":"阿里聚安全",
    "libtup.so":"腾讯",
    "libexec.so":"腾讯",
    "libshell.so":"腾讯",
    "mix.dex":"腾讯",
    "lib/armeabi/mix.dex":"腾讯",
    "lib/armeabi/mixz.dex":"腾讯",
    "libtosprotection.armeabi.so":"腾讯御安全",
    "libtosprotection.armeabi-v7a.so":"腾讯御安全",
    "libtosprotection.x86.so":"腾讯御安全",
    "libnesec.so":"网易易盾",
    "libAPKProtect.so":"APKProtect",
    "libkwscmm.so":"几维安全",
    "libkwscr.so":"几维安全",
    "libkwslinker.so":"几维安全",
    "libx3g.so":"顶象科技",
    "libapssec.so":"盛大",
    "librsprotect.so":"瑞星"
}
