#-*- coding: utf-8 -*-
from __future__ import division

from datetime import datetime
import argparse
from zipfile import BadZipfile
import platform
import os
import collections
from tools.modified.androguard.core.bytecodes import apk
from tools.modified.androguard.core.bytecodes import dvm
from tools.modified.androguard.core.analysis import analysis

from util import *
from writer import Writer
"""
-f 待分析的apk文件
-o 指定分析报告的输出路径
"""


#TODO 增加选项 过滤掉不想检测的包
def parse_argument():
	parser = argparse.ArgumentParser(description='AndroBugs Framework - Android App Security Vulnerability Scanner')
	parser.add_argument("-f", "--apk_file", help="APK File to analyze", type=str, required=True)
	parser.add_argument("-e", "--extra", help="1)Do not check(default)  2)Check  security class names, method names and native methods", type=int, required=False, default=1)
	parser.add_argument("-c", "--line_max_output_characters", help="Setup the maximum characters of analysis output in a line", type=int, required=False)
	parser.add_argument("-x", "--exclude_classes", help="Specify the classes that you do not want to detect")

	#When you want to use "report_output_dir", remember to use "os.path.join(args.report_output_dir, [filename])"
	parser.add_argument("-o", "--report_output_dir", help="Analysis Report Output Directory", type=str, required=False, default=DIRECTORY_REPORT_OUTPUT)

	args = parser.parse_args()
	return args

def __analyze(writer, p_apk_file) :

	"""
		Exception:
			apk_file_not_exist [apk文件不存在]
			classes_dex_not_in_apk  [apk中没有classes.dex]
	"""

	# 计算执行时间
	watch_start = datetime.now()

	efficientStringSearchEngine = EfficientStringSearchEngine()   # 据说是高效的字符串搜索引擎
	# 设置不需要检测的包名，到时候分析的时候可以忽略掉，节省时间。
	filteringEngine = FilteringEngine(ENABLE_EXCLUDE_CLASSES, STR_LIST_EXCLUDE_CLASSES)

	#init_line_max_by_platform(args)    # 根据不同平台初始化每行输出的字符数

	APK_FILE_NAME_STRING = p_apk_file
	apk_Path = APK_FILE_NAME_STRING

	if (".." in p_apk_file) :
		raise ExpectedException("apk_file_name_slash_twodots_error", "APK file name should not contain slash(/) or two dots(..) (File: " + apk_Path + ").")

	if not os.path.isfile(apk_Path) :
		raise ExpectedException("apk_file_not_exist", "APK file not exist (File: " + apk_Path + ").")

	apk_filepath_absolute = os.path.abspath(apk_Path)

	writer.writeHeader_ForceNoPrint("apk_filepath_absolute", apk_filepath_absolute)

	apk_file_size = float(os.path.getsize(apk_filepath_absolute)) / (1024 * 1024)
	writer.writeHeader_ForceNoPrint("apk_file_size", apk_file_size)

	writer.writeHeader_ForceNoPrint("time_starting_analyze", datetime.utcnow())

	a = apk.APK(apk_Path)

	package_name = a.get_package()

	if isNullOrEmptyString(package_name, True) :
		raise ExpectedException("package_name_empty", "Package name is empty (File: " + apk_Path + ").")

	writer.writeHeader("platform", "Android", "Platform")
	writer.writeHeader("package_name", str(package_name), "Package Name")

	# Check: http://developer.android.com/guide/topics/manifest/manifest-element.html
	if not isNullOrEmptyString(a.get_androidversion_name()):
		try :
			writer.writeHeader("package_version_name", str(a.get_androidversion_name()), "Package Version Name")
		except :
			writer.writeHeader("package_version_name", a.get_androidversion_name().encode('ascii', 'ignore'), "Package Version Name")

	if not isNullOrEmptyString(a.get_androidversion_code()):
		try :
			writer.writeHeader("package_version_code", int(a.get_androidversion_code()), "Package Version Code")
		except ValueError :
			writer.writeHeader("package_version_code", a.get_androidversion_code(), "Package Version Code")

	if len(a.get_dex()) == 0:
		raise ExpectedException("classes_dex_not_in_apk", "Broken APK file. \"classes.dex\" file not found (File: " + apk_Path + ").")

	# 判断 minSdkVersion和targetSdkVersion
	try:
		str_min_sdk_version = a.get_min_sdk_version()
		if (str_min_sdk_version is None) or (str_min_sdk_version == "") :
			raise ValueError
		else:
			int_min_sdk = int(str_min_sdk_version)
			writer.writeHeader("minSdk", int_min_sdk, "Min Sdk")
	except ValueError:
		writer.writeHeader("minSdk", 1, "Min Sdk")
		int_min_sdk = 1

	try:
		str_target_sdk_version = a.get_target_sdk_version()
		if (str_target_sdk_version is None) or (str_target_sdk_version == "") :
			raise ValueError
		else:
			int_target_sdk = int(str_target_sdk_version)
			writer.writeHeader("targetSdk", int_target_sdk, "Target Sdk")
	except ValueError:
		# Check: http://developer.android.com/guide/topics/manifest/uses-sdk-element.html
		# If not set, the default value equals that given to minSdkVersion.
		int_target_sdk = int_min_sdk

	md5, sha1, sha256 = get_hashes_by_filename(APK_FILE_NAME_STRING)
	writer.writeHeader("file_md5", md5, "MD5   ")
	writer.writeHeader("file_sha1", sha1, "SHA1  ")
	writer.writeHeader("file_sha256", sha256, "SHA256")

	d = dvm.DalvikVMFormat(a.get_dex())
	vmx = analysis.VMAnalysis(d)

	cm = d.get_class_manager()
	# 打印出各个dex的名字
	dex_names = a.get_dex_names()
	print(dex_names)

	analyze_start = datetime.now()

	#all_permissions = a.get_permissions()  # 所有的权限

	allstrings = d.get_strings()           # 所有的字符串
	allurls_strip_duplicated = []

	list_exported_components = []            # 导出的组件，会在多个检测函数中用到

	print("------------------------------------------------------------")
	exception_url_string = ["http://example.com",
							"http://example.com/",
							"http://www.example.com",
							"http://www.example.com/",
							"http://www.google-analytics.com/collect",
							"http://www.google-analytics.com",
							"http://hostname/?",
							"http://hostname/"]

	for line in allstrings:
		if re.match('http\:\/\/(.+)', line):    #^https?\:\/\/(.+)$
			allurls_strip_duplicated.append(line)

	allurls_strip_non_duplicated = sorted(set(allurls_strip_duplicated))
	allurls_strip_non_duplicated_final = []

	if allurls_strip_non_duplicated:
		for url in allurls_strip_non_duplicated :
			if (url not in exception_url_string) and (not url.startswith("http://schemas.android.com/")) and \
													 (not url.startswith("http://www.w3.org/")) and \
													 (not url.startswith("http://apache.org/")) and \
													 (not url.startswith("http://xml.org/")) and \
													 (not url.startswith("http://localhost/")) and \
													 (not url.startswith("http://java.sun.com/")) and \
													 (not url.endswith("/namespace")) and \
													 (not url.endswith("-dtd")) and \
													 (not url.endswith(".dtd")) and \
													 (not url.endswith("-handler")) and \
													 (not url.endswith("-instance")) :
				# >>>>STRING_SEARCH<<<<
				efficientStringSearchEngine.add_search_item(url, url, False)	#use url as "key"

				allurls_strip_non_duplicated_final.append(url)

	# 检测开始
	##############################################################
	# 先检测壳
	check_packer(a)

	#start the search core engine
	efficientStringSearchEngine.search(d, allstrings)

	# 非HTTPs的URL检测
	check_VUL_SSL_URLS_NOT_IN_HTTPS(allurls_strip_non_duplicated_final, efficientStringSearchEngine, filteringEngine, writer)

	# AndroidManifest文件debuggable配置检测
	check_VUL_DEBUGGABLE(a, writer)

	# AndroidManifest危险ProtectionLevel权限检测
	PermissionName_to_ProtectionLevel = check_VUL_PERMISSION_DANGEROUS(a, writer)

	# AndroidManifest组件导出检测(activity, activity-alias, service, receiver):
	list_exported_components = check_VUL_PERMISSION_EXPORTED(PermissionName_to_ProtectionLevel, a, writer)

	# AndroidManifest Content Provider导出检测
	check_VUL_PERMISSION_PROVIDER_EXPORTED(PermissionName_to_ProtectionLevel, a, int_target_sdk, writer)

	# WebView远程代码执行漏洞检测
	check_VUL_WEBVIEW_RCE(d, filteringEngine, vmx, writer)

	# SSL主机名弱校验漏洞检测
	dic_path_HOSTNAME_INNER_VERIFIER_new_instance = check_VUL_SSL_CN1(d, filteringEngine, vmx, writer)

	# SSL关闭主机名验证检测
	check_VUL_SSL_CN2(d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance, filteringEngine, vmx, writer)

	# SSL不安全组件检测
	check_VUL_SSL_CN3(d, filteringEngine, vmx, writer)

	# HttpHost检测
	check_VUL_SSL_DEFAULT_SCHEME_NAME(d, filteringEngine, vmx, writer)

	# WebView忽略SSL证书错误漏洞检测
	check_VUL_SSL_WEBVIEW(d, filteringEngine, vmx, writer)

	# WebView潜在XSS漏洞检测
	check_VUL_WEBVIEW_JS_ENABLED(d, filteringEngine, vmx, writer)

	# 数据库任意读写漏洞检测
	check_VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE(d, filteringEngine, vmx, writer)

	# Fragment注入漏洞检测 (prior to Android 4.4)
	check_VUL_FRAGMENT_INJECTION(d, filteringEngine, int_target_sdk, writer, list_exported_components)

	# WebView File域同源策略绕过漏洞检测
	check_VUL_WEBVIEW_ALLOW_FILE_ACCESS(cm, d, filteringEngine, vmx, writer)

	# AndroidManifest allowBackup标志检测
	check_VUL_ALLOW_BACKUP(a, writer)

	# SSL证书弱校验漏洞检测
	check_VUL_SSL_X509(d, writer)

	# 日志泄露风险检测
	#check_VUL_LOG_DISCLOSURE(d, filteringEngine, vmx, writer)

	# APP通用型拒绝服务漏洞检测
	check_VUL_GENERAL_DOS(d, filteringEngine, vmx, writer, cm, list_exported_components)

	# WebView密码明文存储漏洞检测
	check_VUL_WEBVIEW_CLEAR_PASSWORD(d, filteringEngine, vmx,writer,cm)

	# 动态注册广播组件暴露风险检测
	check_VUL_DYNAMIC_BROADCAST(d, filteringEngine, vmx, writer)

	# 所谓的ZipperDown检测
	check_VUL_ZIPPERDOWN(d, filteringEngine, vmx, writer)
        
        # 外部DEX文件动态加载
        check_VUL_DYNAMIC_CODE_LOADING(d, filteringEngine, vmx, writer)

        # 访问外部存储设备（SD卡）
        check_VUL_EXTERNAL_STORAGE_ACCESS(d, filteringEngine, vmx, writer)

	#TODO 更多漏洞检测参考：https://github.com/programa-stic/Marvin-static-Analyzer

	writer.completeWriter()
	writer.writeHeader_ForceNoPrint("vector_total_count", writer.get_total_vector_count())
	##############################################################
	# 检测结束

	#StopWatch
	now = datetime.now()
	watch_total_elapsed_time = now - watch_start
	watch_analyze_time = now - analyze_start
	watch_loading_vm = analyze_start - watch_start

	writer.writeHeader_ForceNoPrint("time_total", watch_total_elapsed_time.total_seconds())  # 总用时
	writer.writeHeader_ForceNoPrint("time_analyze", watch_analyze_time.total_seconds())      # 分析用时
	writer.writeHeader_ForceNoPrint("time_loading_vm", watch_loading_vm.total_seconds())     # 载入vm用时

	writer.update_analyze_status("success")
	writer.writeHeader_ForceNoPrint("time_finish_analyze", datetime.utcnow())


def check_VUL_EXTERNAL_STORAGE_ACCESS(d, filteringEngine, vmx, writer):
	paths_ExternalStorageAccess = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;")
	paths_ExternalStorageAccess = filteringEngine.filter_list_of_paths(d, paths_ExternalStorageAccess)
	if paths_ExternalStorageAccess:
		writer.startWriter("EXTERNAL_STORAGE_ACCESS", VUL_EXTERNAL_STORAGE['level'], VUL_EXTERNAL_STORAGE['name'], VUL_EXTERNAL_STORAGE['desc'], VUL_EXTERNAL_STORAGE['fix'])
		writer.show_paths(d, paths_ExternalStorageAccess)


def check_VUL_DYNAMIC_CODE_LOADING(d, filteringEngine, vmx, writer):
	#Detect dynamic code loading
	paths_DexClassLoader = vmx.get_tainted_packages().search_methods( "Ldalvik/system/DexClassLoader;", ".", ".")
	paths_DexClassLoader = filteringEngine.filter_list_of_paths(d, paths_DexClassLoader)
	if paths_DexClassLoader:
		writer.startWriter("DYNAMIC_CODE_LOADING", VUL_DYNAMIC_CODE_LOADING['level'],  VUL_DYNAMIC_CODE_LOADING['name'], 
			VUL_DYNAMIC_CODE_LOADING['desc'], VUL_DYNAMIC_CODE_LOADING['fix'])
		writer.show_paths(d, paths_DexClassLoader)


def check_VUL_ZIPPERDOWN(d, filteringEngine, vmx, writer):
	path_VUL_ZIPPERDOWN = vmx.get_tainted_packages().search_class_methods_exact_match("Ljava/util/zip/ZipEntry;", "getName",
																			 "()Ljava/lang/String;")
	path_VUL_ZIPPERDOWN = filteringEngine.filter_list_of_paths(d, path_VUL_ZIPPERDOWN)
	if path_VUL_ZIPPERDOWN:
		writer.startWriter("ZIPPERDOWN", VUL_ZIPPERDOWN['level'], VUL_ZIPPERDOWN['name'],
						   VUL_ZIPPERDOWN['desc'], VUL_ZIPPERDOWN['fix'])
		for i in path_VUL_ZIPPERDOWN:
			writer.show_path(d, i)


#TODO 待完善检测getActivity.registerReceiver() 这样形式的调用
def check_VUL_DYNAMIC_BROADCAST(d, filteringEngine, vmx, writer):
	"""
	检测带两个参数的registerReceiver()方法调用
	"""
	path_VUL_DYNAMIC_BROADCAST = vmx.get_tainted_packages().search_methods_exact_match(
		"registerReceiver","(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;)Landroid/content/Intent;")
	path_VUL_DYNAMIC_BROADCAST = filteringEngine.filter_list_of_paths(d, path_VUL_DYNAMIC_BROADCAST)
	if path_VUL_DYNAMIC_BROADCAST:
		writer.startWriter("DYNAMIC_BROADCAST", VUL_DYNAMIC_BROADCAST['level'], VUL_DYNAMIC_BROADCAST['name'],
						   VUL_DYNAMIC_BROADCAST['desc'], VUL_DYNAMIC_BROADCAST['fix'])
		writer.show_paths(d, path_VUL_DYNAMIC_BROADCAST)


def check_VUL_WEBVIEW_CLEAR_PASSWORD(d, filteringEngine, vmx, writer, cm):
	"""
	遍历查找调用了Landroid/webkit/WebSettings;  "setSavePassword", "(Z)V "的函数路径，然后再获取函数参数值，判断参数值
	若为None，说明未设置，而默认值为true
	"""
	# 先查找使用了WebSettings的地方
	pkg_WebView_WebSettings = vmx.get_tainted_packages().search_packages("Landroid/webkit/WebSettings;")
	pkg_WebView_WebSettings = filteringEngine.filter_list_of_paths(d, pkg_WebView_WebSettings)
	dict_WebSettings_ClassMethod_to_Path = {}
	for path in pkg_WebView_WebSettings:
		src_class_name, src_method_name, src_descriptor = path.get_src(cm)
		dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)

		dict_name = src_class_name + "->" + src_method_name + src_descriptor
		if dict_name not in dict_WebSettings_ClassMethod_to_Path:
			dict_WebSettings_ClassMethod_to_Path[dict_name] = []

		dict_WebSettings_ClassMethod_to_Path[dict_name].append((dst_method_name + dst_descriptor, path))
	path_WEBVIEW_CLEAR_PASSWORD_vulnerable_ready_to_test = []
	path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func = []
	for class_fun_descriptor, value in dict_WebSettings_ClassMethod_to_Path.items():
		has_Settings = False
		for func_name_descriptor, path in value:
			if func_name_descriptor == "setSavePassword(Z)V":
				has_Settings = True
				# Add ready-to-test Path list
				path_WEBVIEW_CLEAR_PASSWORD_vulnerable_ready_to_test.append(path)
				break

		if not has_Settings:
			# Add vulnerable Path list
			path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func.append(class_fun_descriptor)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d,
																	path_WEBVIEW_CLEAR_PASSWORD_vulnerable_ready_to_test):
		if (i.getResult()[1] == 0x1):  # setSavePassword is true

			path = i.getPath()
			src_class_name, src_method_name, src_descriptor = path.get_src(cm)
			dict_name = src_class_name + "->" + src_method_name + src_descriptor

			if dict_name not in path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func:
				path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func.append(dict_name)
	if path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func:
		path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func = sorted(
			set(path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func))
		writer.startWriter("WEBVIEW_CLEAR_PASSWORD", VUL_WEBVIEW_CLEAR_PASSWORD['level'], VUL_WEBVIEW_CLEAR_PASSWORD['name'],
						   VUL_WEBVIEW_CLEAR_PASSWORD['desc'], VUL_WEBVIEW_CLEAR_PASSWORD['fix'], ["WebView"])
		for i in path_WEBVIEW_CLEAR_PASSWORD_confirm_vulnerable_src_class_func:
			writer.write(i)


def check_VUL_GENERAL_DOS(d, filteringEngine, vmx, writer, cm, p_list_exported_components):
	"""
	判断是否调用了这四个方法（getParcelableExtra，getParcelable，getSerializableExtra，getSerializable），
	暂时没有实现对调用这个四个方法的代码块是否在try/catch内的检测，所以需要提示用户自己检测
	参考：https://www.appscan.io/app-report.html?id=2aa5423c745e2e0cdc29201f3c6b771b527db35b
	"""
	path_VUL_GENERAL_DOS = []          # 检测到的存在DOS漏洞组件的路径
	path_VUL_GENERAL_DOS_EXPORTED = [] # 检测到的存在DOS漏洞的导出组件的路径
	path_getParcelableExtra = vmx.get_tainted_packages().search_methods_exact_match("getParcelableExtra",
														  "(Ljava/lang/String;)Landroid/os/Parcelable;")
	path_getParcelable = vmx.get_tainted_packages().search_methods_exact_match("getParcelable",
														  "(Ljava/lang/String;)Landroid/os/Parcelable;")
	path_getSerializableExtra = vmx.get_tainted_packages().search_methods_exact_match("getSerializableExtra",
														  "(Ljava/lang/String;)Ljava/io/Serializable;")
	path_getSerializable = vmx.get_tainted_packages().search_methods_exact_match("getSerializable",
														  "(Ljava/lang/String;)Ljava/io/Serializable;")
	if path_getParcelableExtra or path_getParcelable or path_getSerializableExtra or path_getSerializable:
		for i in path_getParcelableExtra:
			path_VUL_GENERAL_DOS.append(i)
		for i in path_getParcelable:
			path_VUL_GENERAL_DOS.append(i)
		for i in path_getSerializableExtra:
			path_VUL_GENERAL_DOS.append(i)
		for i in path_getSerializable:
			path_VUL_GENERAL_DOS.append(i)
		# 先找出所有符合这个方法调用的，然后过滤掉不需要查找的包名 "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
		path_VUL_GENERAL_DOS = filteringEngine.filter_list_of_paths(d, path_VUL_GENERAL_DOS)
		for path in path_VUL_GENERAL_DOS:
			src_class_name, src_method_name, src_descriptor = path.get_src(cm)
			if src_class_name in p_list_exported_components:    # 若源class中存在导出的组件
				path_VUL_GENERAL_DOS_EXPORTED.append(path)

		if path_VUL_GENERAL_DOS_EXPORTED:
			writer.startWriter("GENERAL_DOS", VUL_GENERAL_DOS['level'], VUL_GENERAL_DOS['name'],
							   VUL_GENERAL_DOS['desc'], VUL_GENERAL_DOS['fix'])
			writer.show_paths(d, path_VUL_GENERAL_DOS_EXPORTED)


# 检测壳
def check_packer(pApk):
	"""
	遍历apk的文件列表，看是否有PACKER_FEATURES列表中的.so文件名
	"""
	is_contain_packer = False
	packer_type = ""   # 壳的类型（具体哪种壳）
	for fileName in pApk.zip.namelist():
		for packer in PACKER_FEATURES.keys():
			if packer in fileName:  # 若相对路径文件名中出现了这个壳的字符串
				is_contain_packer = True
				packer_type = PACKER_FEATURES[packer]
				break
	if is_contain_packer:
		print("[*] 经检测，该apk使用了" + packer_type +"进行加固。请上传未加固的apk！")
		exit(1)


def check_VUL_LOG_DISCLOSURE(d, filteringEngine, vmx, writer):
	"""
	检测日志泄露风险检测，android.util.Log.v|d|i|w|e()方法
	"""
	path_LOG_DISCLOSURE = []
	path_LOG_V = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/util/Log;", "v",
																			 "(Ljava/lang/String; Ljava/lang/String;)I")
	path_LOG_D = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/util/Log;", "d",
																			 "(Ljava/lang/String; Ljava/lang/String;)I")
	path_LOG_I = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/util/Log;", "i",
																			 "(Ljava/lang/String; Ljava/lang/String;)I")
	path_LOG_W = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/util/Log;", "w",
																			 "(Ljava/lang/String; Ljava/lang/String;)I")
	path_LOG_E = vmx.get_tainted_packages().search_class_methods_exact_match("Landroid/util/Log;", "e",
																			 "(Ljava/lang/String; Ljava/lang/String;)I")

	if path_LOG_V or path_LOG_D or path_LOG_I or path_LOG_W or path_LOG_E:
		for i in path_LOG_V:
			path_LOG_DISCLOSURE.append(i)
		for i in path_LOG_D:
			path_LOG_DISCLOSURE.append(i)
		for i in path_LOG_D:
			path_LOG_DISCLOSURE.append(i)
		for i in path_LOG_D:
			path_LOG_DISCLOSURE.append(i)
		for i in path_LOG_D:
			path_LOG_DISCLOSURE.append(i)
	path_LOG_DISCLOSURE = filteringEngine.filter_list_of_paths(d, path_LOG_DISCLOSURE)
	if path_LOG_DISCLOSURE:
		writer.startWriter("LOG_DISCLOSURE", VUL_LOG_DISCLOSURE['level'], VUL_LOG_DISCLOSURE['name'], VUL_LOG_DISCLOSURE['desc'],
						   VUL_LOG_DISCLOSURE['fix'])
		writer.show_paths(d, path_LOG_DISCLOSURE)


def check_VUL_SSL_X509(d, writer):
	methods_X509TrustManager_list = get_method_ins_by_implement_interface_and_method_desc_dict(d, [
		"Ljavax/net/ssl/X509TrustManager;"], TYPE_COMPARE_ANY,["getAcceptedIssuers()[Ljava/security/cert/X509Certificate;",
																"checkClientTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V",
																"checkServerTrusted([Ljava/security/cert/X509Certificate; Ljava/lang/String;)V"])
	list_X509Certificate_Critical_class = []
	list_X509Certificate_Warning_class = []
	for class_name, method_list in methods_X509TrustManager_list.items():
		ins_count = 0

		for method in method_list:
			for ins in method.get_instructions():
				ins_count = ins_count + 1

		if ins_count <= 4:
			# Critical
			list_X509Certificate_Critical_class.append(class_name)
		else:
			# Warning
			list_X509Certificate_Warning_class.append(class_name)
	if list_X509Certificate_Critical_class or list_X509Certificate_Warning_class:
		log_level = LEVEL_MEDIUM
		log_partial_prefix_msg = "可能存在漏洞，请手动验证！"

		if list_X509Certificate_Critical_class:
			log_level = LEVEL_HIGH
			log_partial_prefix_msg = "确认存在漏洞！"

		list_X509Certificate_merge_list = []
		list_X509Certificate_merge_list.extend(list_X509Certificate_Critical_class)
		list_X509Certificate_merge_list.extend(list_X509Certificate_Warning_class)

		dict_X509Certificate_class_name_to_caller_mapping = {}

		for method in d.get_methods():
			for i in method.get_instructions():  # method.get_instructions(): Instruction
				if i.get_op_value() == 0x22:  # 0x22 = "new-instance"
					if i.get_string() in list_X509Certificate_merge_list:
						referenced_class_name = i.get_string()
						if referenced_class_name not in dict_X509Certificate_class_name_to_caller_mapping:
							dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name] = []
						dict_X509Certificate_class_name_to_caller_mapping[referenced_class_name].append(method)

		writer.startWriter("SSL_X509", log_level, VUL_SSL_X509['name'],
						   log_partial_prefix_msg + VUL_SSL_X509['desc'], VUL_SSL_X509['fix'], ["SSL_Security"])
		if list_X509Certificate_Critical_class:
			for name in list_X509Certificate_Critical_class:
				writer.write("=> " + name)
				if name in dict_X509Certificate_class_name_to_caller_mapping:
					for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
						writer.write(
							"      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())

		if list_X509Certificate_Warning_class:
			for name in list_X509Certificate_Warning_class:
				writer.write("=> " + name)
				if name in dict_X509Certificate_class_name_to_caller_mapping:
					for used_method in dict_X509Certificate_class_name_to_caller_mapping[name]:
						writer.write(
							"      -> used by: " + used_method.get_class_name() + "->" + used_method.get_name() + used_method.get_descriptor())


def check_VUL_ALLOW_BACKUP(a, writer):
	if a.is_adb_backup_enabled():
		writer.startWriter("ALLOW_BACKUP", VUL_LOG_DISCLOSURE['level'], VUL_ALLOW_BACKUP['name'],
						   VUL_ALLOW_BACKUP['desc'], VUL_ALLOW_BACKUP['fix'])


def check_VUL_WEBVIEW_ALLOW_FILE_ACCESS(cm, d, filteringEngine, vmx, writer):
	pkg_WebView_WebSettings = vmx.get_tainted_packages().search_packages("Landroid/webkit/WebSettings;")
	pkg_WebView_WebSettings = filteringEngine.filter_list_of_paths(d, pkg_WebView_WebSettings)
	dict_WebSettings_ClassMethod_to_Path = {}
	for path in pkg_WebView_WebSettings:
		src_class_name, src_method_name, src_descriptor = path.get_src(cm)
		dst_class_name, dst_method_name, dst_descriptor = path.get_dst(cm)

		dict_name = src_class_name + "->" + src_method_name + src_descriptor
		if dict_name not in dict_WebSettings_ClassMethod_to_Path:
			dict_WebSettings_ClassMethod_to_Path[dict_name] = []

		dict_WebSettings_ClassMethod_to_Path[dict_name].append((dst_method_name + dst_descriptor, path))
	path_setAllowFileAccess_vulnerable_ready_to_test = []
	path_setAllowFileAccess_confirm_vulnerable_src_class_func = []
	for class_fun_descriptor, value in dict_WebSettings_ClassMethod_to_Path.items():
		has_Settings = False
		for func_name_descriptor, path in value:
			if func_name_descriptor == "setAllowFileAccess(Z)V":
				has_Settings = True
				# Add ready-to-test Path list
				path_setAllowFileAccess_vulnerable_ready_to_test.append(path)
				break

		if not has_Settings:
			# Add vulnerable Path list
			path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(class_fun_descriptor)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d,
																	path_setAllowFileAccess_vulnerable_ready_to_test):
		if (i.getResult()[1] == 0x1):  # setAllowFileAccess is true

			path = i.getPath()
			src_class_name, src_method_name, src_descriptor = path.get_src(cm)
			dict_name = src_class_name + "->" + src_method_name + src_descriptor

			if dict_name not in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
				path_setAllowFileAccess_confirm_vulnerable_src_class_func.append(dict_name)
	if path_setAllowFileAccess_confirm_vulnerable_src_class_func:
		path_setAllowFileAccess_confirm_vulnerable_src_class_func = sorted(
			set(path_setAllowFileAccess_confirm_vulnerable_src_class_func))
		writer.startWriter("WEBVIEW_ALLOW_FILE_ACCESS", VUL_WEBVIEW_ALLOW_FILE_ACCESS['level'], VUL_WEBVIEW_ALLOW_FILE_ACCESS['name'],
						   VUL_WEBVIEW_ALLOW_FILE_ACCESS['desc'], VUL_WEBVIEW_ALLOW_FILE_ACCESS['fix'], ["WebView"])
		for i in path_setAllowFileAccess_confirm_vulnerable_src_class_func:
			writer.write(i)


def check_VUL_FRAGMENT_INJECTION(d, filteringEngine, int_target_sdk, writer, p_list_exported_components):
	prog = re.compile("Landroid/support/v(\d*)/app/Fragment;")
	REGEXP_EXCLUDE_CLASSESd_fragment_class = re.compile("(Landroid/support/)|(Lcom/actionbarsherlock/)")
	list_Fragment = []
	has_any_fragment = False
	for cls in d.get_classes():  # 对所有class进行遍历，找出Fragment的子类
		if (cls.get_superclassname() == "Landroid/app/Fragment;") or prog.match(cls.get_superclassname()):
			if not REGEXP_EXCLUDE_CLASSESd_fragment_class.match(cls.get_name()):
				# Exclude the classes from library itself to make the finding more precise and to check the user really use fragment, not just include the libs
				has_any_fragment = True
				list_Fragment.append(cls.get_name())
	list_Frag_vul_NonMethod_classes = []
	list_Frag_vul_Method_OnlyReturnTrue_methods = []
	list_Frag_vul_Method_NoIfOrSwitch_methods = []
	list_Fragment = filteringEngine.filter_list_of_classes(list_Fragment)
	if list_Fragment:
		for cls in d.get_classes():
			if (cls.get_superclassname() == "Landroid/preference/PreferenceActivity;") or (
					cls.get_superclassname() == "Lcom/actionbarsherlock/app/SherlockPreferenceActivity;"):
				boolHas_isValidFragment = False
				method_isValidFragment = None
				for method in cls.get_methods():
					if (method.get_name() == "isValidFragment") and (
							method.get_descriptor() == "(Ljava/lang/String;)Z"):
						boolHas_isValidFragment = True
						method_isValidFragment = method
						break
				if boolHas_isValidFragment:
					register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(
						method_isValidFragment.get_instructions())
					if register_analyzer.get_ins_return_boolean_value():
						list_Frag_vul_Method_OnlyReturnTrue_methods.append(method_isValidFragment)
					else:
						if not register_analyzer.has_if_or_switch_instructions():  # do not have "if" or "switch" op in instructions of method
							list_Frag_vul_Method_NoIfOrSwitch_methods.append(method_isValidFragment)
				else:
					list_Frag_vul_NonMethod_classes.append(cls.get_name())
	list_Frag_vul_NonMethod_classes = filteringEngine.filter_list_of_classes(
		list_Frag_vul_NonMethod_classes)
	list_Frag_vul_Method_OnlyReturnTrue_methods = filteringEngine.filter_list_of_methods(
		list_Frag_vul_Method_OnlyReturnTrue_methods)
	list_Frag_vul_Method_NoIfOrSwitch_methods = filteringEngine.filter_list_of_methods(
		list_Frag_vul_Method_NoIfOrSwitch_methods)
	is_a = [a for a in list_Frag_vul_NonMethod_classes if a in p_list_exported_components]
	is_b = [b for b in list_Frag_vul_Method_OnlyReturnTrue_methods if b in p_list_exported_components]
	is_c = [a for c in list_Frag_vul_Method_NoIfOrSwitch_methods if c in p_list_exported_components]
	# 在这个类是导出的组件的情况下
	if list_Frag_vul_NonMethod_classes or list_Frag_vul_Method_OnlyReturnTrue_methods or list_Frag_vul_Method_NoIfOrSwitch_methods:
		if (is_a or is_b or is_c):
			writer.startWriter("FRAGMENT_INJECTION", VUL_FRAGMENT_INJECTION['level'], VUL_FRAGMENT_INJECTION['name'],
							   VUL_FRAGMENT_INJECTION['desc'], VUL_FRAGMENT_INJECTION['fix'], None)
	
			if list_Frag_vul_NonMethod_classes:
				if int_target_sdk >= 19:
					writer.write("当Android api >=19时，要重写每一个PreferenceActivity类下的isValidFragment()方法以避免异常抛出.")
					for i in list_Frag_vul_NonMethod_classes:  # Notice: Each element in the list is NOT method, but String
						writer.write("    " + i)
				else:
					writer.write("当Android api < 19时，如果在PreferenceActivity内没有引用任何fragment，建议重写isValidFragment()并返回false.")
					for i in list_Frag_vul_NonMethod_classes:  # Notice: Each element in the list is NOT method, but String
						writer.write("    " + i)
	
			if list_Frag_vul_Method_OnlyReturnTrue_methods:
				writer.write(
					"You override 'isValidFragment' and only return \"true\" in those classes. You should use \"if\" condition to check whether the fragment is valid:")
				writer.write(
					"(Example code: http://stackoverflow.com/questions/19973034/isvalidfragment-android-api-19/20139823#20139823)")
				for method in list_Frag_vul_Method_OnlyReturnTrue_methods:
					writer.write("    " + method.easy_print())
	
			if list_Frag_vul_Method_NoIfOrSwitch_methods:
				writer.write(
					"Please make sure you check the valid fragment inside the overridden 'isValidFragment' method:")
				for method in list_Frag_vul_Method_NoIfOrSwitch_methods:
					writer.write("    " + method.easy_print())
	
			if list_Fragment:
				writer.write("All of the potential vulnerable \"fragment\":")
				for i in list_Fragment:
					writer.write("    " + i)


def check_VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE(d, filteringEngine, vmx, writer):
	"""
		MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE checking:

		MODE_WORLD_READABLE = 1
		MODE_WORLD_WRITEABLE = 2
		MODE_WORLD_READABLE + MODE_WORLD_WRITEABLE = 3

		http://jimmy319.blogspot.tw/2011/07/android-internal-storagefile-io.html

		Example Java Code:
			FileOutputStream outputStream = openFileOutput("Hello_World", Activity.MODE_WORLD_READABLE);

		Example Smali Code:
			const-string v3, "Hello_World"
			const/4 v4, 0x1
		    invoke-virtual {p0, v3, v4}, Lcom/example/android_mode_world_testing/MainActivity;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;

	added by cqq:
	由于创建world-writable/world-readable的文件非常危险，MODE_WORLD_READABLE 和MODE_WORLD_WRITEABLE 已在API level 17废止。
	参考：https://developer.android.com/reference/android/content/Context#MODE_WORLD_READABLE
	"""
	list_path_openOrCreateDatabase = []
	list_path_openOrCreateDatabase2 = []
	list_path_getDir = []
	list_path_getSharedPreferences = []
	list_path_openFileOutput = []
	path_openOrCreateDatabase = vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase",
																					  "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory;)Landroid/database/sqlite/SQLiteDatabase;")
	path_openOrCreateDatabase = filteringEngine.filter_list_of_paths(d, path_openOrCreateDatabase)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openOrCreateDatabase):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openOrCreateDatabase.append(i.getPath())
	path_openOrCreateDatabase2 = vmx.get_tainted_packages().search_methods_exact_match("openOrCreateDatabase",
																					   "(Ljava/lang/String; I Landroid/database/sqlite/SQLiteDatabase$CursorFactory; Landroid/database/DatabaseErrorHandler;)Landroid/database/sqlite/SQLiteDatabase;")
	path_openOrCreateDatabase2 = filteringEngine.filter_list_of_paths(d, path_openOrCreateDatabase2)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openOrCreateDatabase2):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openOrCreateDatabase2.append(i.getPath())
	path_getDir = vmx.get_tainted_packages().search_methods_exact_match("getDir",
																		"(Ljava/lang/String; I)Ljava/io/File;")
	path_getDir = filteringEngine.filter_list_of_paths(d, path_getDir)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_getDir):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_getDir.append(i.getPath())
	path_getSharedPreferences = vmx.get_tainted_packages().search_methods_exact_match("getSharedPreferences",
																					  "(Ljava/lang/String; I)Landroid/content/SharedPreferences;")
	path_getSharedPreferences = filteringEngine.filter_list_of_paths(d, path_getSharedPreferences)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_getSharedPreferences):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_getSharedPreferences.append(i.getPath())
	path_openFileOutput = vmx.get_tainted_packages().search_methods_exact_match("openFileOutput",
																				"(Ljava/lang/String; I)Ljava/io/FileOutputStream;")
	path_openFileOutput = filteringEngine.filter_list_of_paths(d, path_openFileOutput)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_openFileOutput):
		if (0x1 <= i.getResult()[2] <= 0x3):
			list_path_openFileOutput.append(i.getPath())
	if list_path_openOrCreateDatabase or list_path_openOrCreateDatabase2 or list_path_getDir or list_path_getSharedPreferences or list_path_openFileOutput:
		writer.startWriter("MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE", VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE['level'],
						   VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE['name'],
						   VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE['desc'],
						   VUL_MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE['fix'])

		if list_path_openOrCreateDatabase:
			writer.write("[openOrCreateDatabase - 3 params]")
			for i in list_path_openOrCreateDatabase:
				writer.show_path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_openOrCreateDatabase2:
			writer.write("[openOrCreateDatabase - 4 params]")
			for i in list_path_openOrCreateDatabase2:
				writer.show_path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_getDir:
			writer.write("[getDir]")
			for i in list_path_getDir:
				writer.show_path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_getSharedPreferences:
			writer.write("[getSharedPreferences]")
			for i in list_path_getSharedPreferences:
				writer.show_path(d, i)
			writer.write("--------------------------------------------------")
		if list_path_openFileOutput:
			writer.write("[openFileOutput]")
			for i in list_path_openFileOutput:
				writer.show_path(d, i)
			writer.write("--------------------------------------------------")


def check_VUL_WEBVIEW_JS_ENABLED(d, filteringEngine, vmx, writer):
	"""
		Java Example code:
	    	webView1 = (WebView)findViewById(R.id.webView1);
			webView1.setWebViewClient(new ExtendedWebView());
			WebSettings webSettings = webView1.getSettings();
			webSettings.setJavaScriptEnabled(true);

	    Smali Example code:
			const/4 v1, 0x1
    		invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
	"""
	list_setJavaScriptEnabled_XSS = []
	path_setJavaScriptEnabled_XSS = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V")
	path_setJavaScriptEnabled_XSS = filteringEngine.filter_list_of_paths(d, path_setJavaScriptEnabled_XSS)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_setJavaScriptEnabled_XSS):
		if i.getResult()[1] is None:
			continue
		if i.getResult()[1] == 0x1:
			list_setJavaScriptEnabled_XSS.append(i.getPath())
	if list_setJavaScriptEnabled_XSS:
		writer.startWriter("WEBVIEW_JS_ENABLED", VUL_WEBVIEW_JS_ENABLED['level'], VUL_WEBVIEW_JS_ENABLED['name'],
						   VUL_WEBVIEW_JS_ENABLED['desc'], VUL_WEBVIEW_JS_ENABLED['fix'], ["WebView"])
		for i in list_setJavaScriptEnabled_XSS:
			writer.show_path(d, i)


def check_VUL_SSL_WEBVIEW(d, filteringEngine, vmx, writer):
	# First, find out who calls setWebViewClient
	path_webviewClient_new_instance = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Landroid/webkit/WebView;", "setWebViewClient", "(Landroid/webkit/WebViewClient;)V")
	dic_webviewClient_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(d,
																												 analysis,
																												 path_webviewClient_new_instance,
																												 1)
	# Second, find which class and method extends it
	list_webviewClient = []
	methods_webviewClient = get_method_ins_by_superclass_and_method(d, ["Landroid/webkit/WebViewClient;"],
																	"onReceivedSslError",
																	"(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V")
	for method in methods_webviewClient:
		if is_kind_string_in_ins_method(method, "Landroid/webkit/SslErrorHandler;->proceed()V"):
			list_webviewClient.append(method)
	list_webviewClient = filteringEngine.filter_list_of_methods(list_webviewClient)
	if list_webviewClient:
		writer.startWriter("SSL_WEBVIEW", VUL_SSL_WEBVIEW['level'], VUL_SSL_WEBVIEW['name'],
						   VUL_SSL_WEBVIEW['desc'], VUL_SSL_WEBVIEW['fix'], ["SSL_Security"])

		for method in list_webviewClient:
			writer.write(method.easy_print())
			# because one class may initialize by many new instances of it
			method_class_name = method.get_class_name()
			if method_class_name in dic_webviewClient_new_instance:
				writer.show_paths(d, dic_webviewClient_new_instance[method_class_name])


def check_VUL_SSL_DEFAULT_SCHEME_NAME(d, filteringEngine, vmx, writer):
	"""
		Check this paper to see why I designed this vector: "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"
		Java Example code:
	    	HttpHost target = new HttpHost(uri.getHost(), uri.getPort(), HttpHost.DEFAULT_SCHEME_NAME);

	    Smali Example code:
	    	const-string v4, "http"
	    	invoke-direct {v0, v2, v3, v4}, Lorg/apache/http/HttpHost;-><init>(Ljava/lang/String; I Ljava/lang/String;)V
	"""
	list_HttpHost_scheme_http = []
	path_HttpHost_scheme_http = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Lorg/apache/http/HttpHost;", "<init>", "(Ljava/lang/String; I Ljava/lang/String;)V")
	path_HttpHost_scheme_http = filteringEngine.filter_list_of_paths(d, path_HttpHost_scheme_http)
	for i in analysis.trace_Register_value_by_Param_in_source_Paths(d, path_HttpHost_scheme_http):
		if i.getResult()[3] is None:
			continue
		if (i.is_string(i.getResult()[3])) and ((i.getResult()[3]).lower() == "http"):
			list_HttpHost_scheme_http.append(i.getPath())
	if list_HttpHost_scheme_http:
		writer.startWriter("SSL_DEFAULT_SCHEME_NAME", VUL_SSL_DEFAULT_SCHEME_NAME['level'], VUL_SSL_DEFAULT_SCHEME_NAME['name'],
						   VUL_SSL_DEFAULT_SCHEME_NAME['desc'], VUL_SSL_DEFAULT_SCHEME_NAME['fix'], ["SSL_Security"])

		for i in list_HttpHost_scheme_http:
			writer.show_path(d, i)


def check_VUL_SSL_CN3(d, filteringEngine, vmx, writer):
	list_getInsecure = []
	path_getInsecure = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Landroid/net/SSLCertificateSocketFactory;", "getInsecure",
		"(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;")
	path_getInsecure = filteringEngine.filter_list_of_paths(d, path_getInsecure)
	if path_getInsecure:
		writer.startWriter("SSL_CN3", VUL_SSL_CN3['level'], VUL_SSL_CN3['name'],
						   VUL_SSL_CN3['desc'], VUL_SSL_CN3['fix'], ["SSL_Security"])
		writer.show_paths(d, path_getInsecure)


def check_VUL_SSL_CN2(d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance, filteringEngine, vmx, writer):
	if "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;" in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
		path_HOSTNAME_INNER_VERIFIER_new_instance = dic_path_HOSTNAME_INNER_VERIFIER_new_instance[
			"Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;"]
	else:
		path_HOSTNAME_INNER_VERIFIER_new_instance = None
	# "vmx.get_tainted_field" will return "None" if nothing found
	field_ALLOW_ALL_HOSTNAME_VERIFIER = vmx.get_tainted_field("Lorg/apache/http/conn/ssl/SSLSocketFactory;",
															  "ALLOW_ALL_HOSTNAME_VERIFIER",
															  "Lorg/apache/http/conn/ssl/X509HostnameVerifier;")
	if field_ALLOW_ALL_HOSTNAME_VERIFIER:
		filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = filteringEngine.filter_list_of_variables(d,
																							  field_ALLOW_ALL_HOSTNAME_VERIFIER.get_paths())
	else:
		filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths = None
	if path_HOSTNAME_INNER_VERIFIER_new_instance or filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
		writer.startWriter("SSL_CN2", VUL_SSL_CN2['level'], VUL_SSL_CN2['name'],
						   VUL_SSL_CN2['desc'], VUL_SSL_CN2['fix'], ["SSL_Security"])
		if filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
			"""
				Example code: 
				SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
				factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
			"""
			for path in filtered_ALLOW_ALL_HOSTNAME_VERIFIER_paths:
				writer.show_single_PathVariable(d, path)

		if path_HOSTNAME_INNER_VERIFIER_new_instance:
			"""
				Example code: 
				SSLSocketFactory factory = SSLSocketFactory.getSocketFactory();
				factory.setHostnameVerifier(new AllowAllHostnameVerifier());
			"""
			# For this one, the exclusion procedure is done on earlier
			writer.show_paths(d, path_HOSTNAME_INNER_VERIFIER_new_instance)


def check_VUL_SSL_CN1(d, filteringEngine, vmx, writer):
	# "类名;"，"方法名"，"(参数类型;)返回值类型"
	path_HOSTNAME_INNER_VERIFIER = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier", "(Ljavax/net/ssl/HostnameVerifier;)V")
	path_HOSTNAME_INNER_VERIFIER2 = vmx.get_tainted_packages().search_class_methods_exact_match(
		"Lorg/apache/http/conn/ssl/SSLSocketFactory;", "setHostnameVerifier",
		"(Lorg/apache/http/conn/ssl/X509HostnameVerifier;)V")
	path_HOSTNAME_INNER_VERIFIER.extend(path_HOSTNAME_INNER_VERIFIER2)
	path_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_paths(d, path_HOSTNAME_INNER_VERIFIER)
	dic_path_HOSTNAME_INNER_VERIFIER_new_instance = filteringEngine.get_class_container_dict_by_new_instance_classname_in_paths(
		d, analysis, path_HOSTNAME_INNER_VERIFIER, 1)  # parameter index 1
	list_HOSTNAME_INNER_VERIFIER = []
	methods_hostnameverifier = get_method_ins_by_implement_interface_and_method(d, ["Ljavax/net/ssl/HostnameVerifier;"],
																				TYPE_COMPARE_ANY, "verify",
																				"(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z")
	for method in methods_hostnameverifier:
		register_analyzer = analysis.RegisterAnalyzerVM_ImmediateValue(method.get_instructions())
		if register_analyzer.get_ins_return_boolean_value():  # Has security problem
			list_HOSTNAME_INNER_VERIFIER.append(method)
	list_HOSTNAME_INNER_VERIFIER = filteringEngine.filter_list_of_methods(list_HOSTNAME_INNER_VERIFIER)
	if list_HOSTNAME_INNER_VERIFIER:
		writer.startWriter("SSL_CN1", VUL_SSL_CN1['level'], VUL_SSL_CN1['name'],
						   VUL_SSL_CN1['desc'], VUL_SSL_CN1['fix'], ["SSL_Security"])

		for method in list_HOSTNAME_INNER_VERIFIER:
			writer.write(method.easy_print())

			# because one class may initialize by many new instances of it
			method_class_name = method.get_class_name()
			if method_class_name in dic_path_HOSTNAME_INNER_VERIFIER_new_instance:
				writer.show_paths(d, dic_path_HOSTNAME_INNER_VERIFIER_new_instance[method_class_name])
	return dic_path_HOSTNAME_INNER_VERIFIER_new_instance


def check_VUL_WEBVIEW_RCE(d, filteringEngine, vmx, writer):
	# "方法名", "(参数1; I 参数2; 参数3;)返回值类型;"
	path_WebView_addJavascriptInterface = vmx.get_tainted_packages().search_methods_exact_match(
		"addJavascriptInterface", "(Ljava/lang/Object; Ljava/lang/String;)V")
	# 先找出所有符合这个方法调用的，然后过滤掉不需要查找的包名 "STR_REGEXP_TYPE_EXCLUDE_CLASSES"
	path_WebView_addJavascriptInterface = filteringEngine.filter_list_of_paths(d, path_WebView_addJavascriptInterface)
	if path_WebView_addJavascriptInterface:
		writer.startWriter("WEBVIEW_RCE", VUL_WEBVIEW_RCE['level'], VUL_WEBVIEW_RCE['name'],
						   VUL_WEBVIEW_RCE['desc'], VUL_WEBVIEW_RCE['fix'], ["WebView", "Remote Code Execution"],
						   "CVE-2013-4710")
		writer.show_paths(d, path_WebView_addJavascriptInterface)


def check_VUL_PERMISSION_PROVIDER_EXPORTED(PermissionName_to_ProtectionLevel, a, int_target_sdk, writer):
	list_ready_to_check = []
	xml = a.get_AndroidManifest()
	for item in xml.getElementsByTagName("provider"):
		name = item.getAttribute("android:name")
		exported = item.getAttribute("android:exported")
		if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):
			# exported 值为true，或者未设置，就继续检查权限
			permission = item.getAttribute("android:permission")
			has_exported = True if (exported != "") else False  # 既不是空也不是false，就认为是true，再继续检测
			list_ready_to_check.append((a.format_value(name), exported, permission, has_exported))
	list_alerting_exposing_providers_no_exported_setting = []  # providers that Did not set exported
	list_alerting_exposing_providers = []  # provider with "true" exported
	for i in list_ready_to_check:  # only exist "exported" provider or not set
		exported = i[1]
		permission = i[2]
		is_dangerous = False
		list_perm = []
		if permission != "":
			list_perm.append(permission)
		if list_perm:  # among "permission" or "readPermission" or "writePermission", any of the permission is set
			for self_defined_permission in list_perm:  # (1)match any (2)ignore permission that is not found
				if self_defined_permission in PermissionName_to_ProtectionLevel:
					protectionLevel = PermissionName_to_ProtectionLevel[self_defined_permission]
					# 总共只有四个权限选项，排除siganature和signatureOrSystem之后的两个说明没有声明较高的权限限制
					if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
						is_dangerous = True
						break
			if (exported == "") and (int_target_sdk < 17) and (is_dangerous):  # targetSdk < 17的情况下Provider默认导出
				list_alerting_exposing_providers_no_exported_setting.append(i)
		else:  # none of any permission
			if exported.lower() == "true":
				is_dangerous = True
			elif (exported == "") and (int_target_sdk < 17):  # targetSdk < 17的情况下Provider默认导出
				list_alerting_exposing_providers_no_exported_setting.append(i)
		if is_dangerous:
			list_alerting_exposing_providers.append(
				i)  # exported="true" and none of the permission are set => of course dangerous
	if list_alerting_exposing_providers or list_alerting_exposing_providers_no_exported_setting:
		if list_alerting_exposing_providers_no_exported_setting:  # providers that Did not set exported
			writer.startWriter("PERMISSION_PROVIDER_EXPORTED",
							   VUL_PERMISSION_PROVIDER_EXPORTED['level'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['name'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['desc'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['fix'])
			for i in list_alerting_exposing_providers_no_exported_setting:
				writer.write(("%10s => %s") % ("provider", i[0]))
		if list_alerting_exposing_providers:  # provider with "true" exported and not enough permission protected on it
			writer.startWriter("PERMISSION_PROVIDER_EXPORTED",
							   VUL_PERMISSION_PROVIDER_EXPORTED['level'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['name'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['desc'],
							   VUL_PERMISSION_PROVIDER_EXPORTED['fix'])
			for i in list_alerting_exposing_providers:
				writer.write(("%10s => %s") % ("provider", i[0]))


def check_VUL_PERMISSION_EXPORTED(PermissionName_to_ProtectionLevel, a, writer):
	find_tags = ["activity", "activity-alias", "service", "receiver"]
	list_ready_to_check = []
	p_list_exported_components = []
	xml = a.get_AndroidManifest()
	for tag in find_tags:
		for item in xml.getElementsByTagName(tag):
			name = item.getAttribute("android:name")
			exported = item.getAttribute("android:exported")
			permission = item.getAttribute("android:permission")
			has_any_actions_in_intent_filter = False
			# 排除掉google的service
			if (not isNullOrEmptyString(name)) and (exported.lower() != "false") and (
					not name.startswith("com.google.")):
				is_ready_to_check = False
				is_action_main = False
				has_any_non_google_actions = False
				is_sync_adapter_service = False
				for sitem in item.getElementsByTagName("intent-filter"):
					for ssitem in sitem.getElementsByTagName("action"):  # 判断action的值
						has_any_actions_in_intent_filter = True  # 存在action
						action_name = ssitem.getAttribute("android:name")
						# 若检测到的action的名字并不以"android"开头，而且并不以"com.android"开头，而且不以"com.google."开头，则认为存在非google定义的action
						if (not action_name.startswith("android.")) and (
								not action_name.startswith("com.android.")):
							has_any_non_google_actions = True
						if (action_name == "android.content.SyncAdapter"):
							is_sync_adapter_service = True
					# 判断action,若为android.intent.action.MAIN，即便这个Activity是导出的，但是也安全（毕竟需要启动的入口啊！）。
					for ssitem in sitem.getElementsByTagName("action"):
						action_name = ssitem.getAttribute("android:name")
						if action_name == "android.intent.action.MAIN":
							is_action_main = True
				if exported == "":  # 若未设置
					if has_any_actions_in_intent_filter:
						is_ready_to_check = True
				elif exported.lower() == "true":  # 设置为true
					is_ready_to_check = True
				if (is_ready_to_check) and (not is_action_main):  # 除开权限外，待检查的组件列表
					list_ready_to_check.append((tag, a.format_value(name), exported, permission,
												has_any_non_google_actions, has_any_actions_in_intent_filter,
												is_sync_adapter_service))
	# 检查权限
	list_implicit_service_components = []
	list_alerting_exposing_components_NonGoogle = []
	list_alerting_exposing_components_Google = []
	for i in list_ready_to_check:
		component = i[0]
		permission = i[3]
		hasAnyNonGoogleActions = i[4]
		has_any_actions_in_intent_filter = i[5]
		is_sync_adapter_service = i[6]
		is_dangerous = False
		if permission == "":  # 未设置android:permission属性，则存在风险
			is_dangerous = True
		else:  # 设置了android:permission属性，则判断是不是Signature或者SignatureOrSystem，而是普通的NORMAL和DANGEROUS
			if permission in PermissionName_to_ProtectionLevel:
				protectionLevel = PermissionName_to_ProtectionLevel[permission]
				if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
					is_dangerous = True
			else:  # cannot find the mapping permission
				is_dangerous = True
		if is_dangerous:
			if (component == "service") and (has_any_actions_in_intent_filter) and (not is_sync_adapter_service):
				list_implicit_service_components.append(i[1])
			if hasAnyNonGoogleActions:
				if i not in list_alerting_exposing_components_NonGoogle:
					list_alerting_exposing_components_NonGoogle.append(i)
			else:
				if i not in list_alerting_exposing_components_Google:
					list_alerting_exposing_components_Google.append(i)
	if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
		writer.startWriter("PERMISSION_EXPORTED", VUL_PERMISSION_EXPORTED['level'], VUL_PERMISSION_EXPORTED['name'],
						   VUL_PERMISSION_EXPORTED['desc'], VUL_PERMISSION_EXPORTED['fix'])
		for i in list_alerting_exposing_components_NonGoogle:
			p_list_exported_components.append(i[1])  # 将导出的组件记录在列表中，待其他检测逻辑使用
			writer.write(("%10s => %s") % (i[0], i[1]))
	return p_list_exported_components


def check_VUL_PERMISSION_DANGEROUS(a, writer):
	"""
		android:permission
		android:readPermission (for ContentProvider)
		android:writePermission (for ContentProvider)
	"""
	# Get a mapping dictionary
	PermissionName_to_ProtectionLevel = a.get_PermissionName_to_ProtectionLevel_mapping()
	dangerous_custom_permissions = []
	for name, protectionLevel in PermissionName_to_ProtectionLevel.items():
		if protectionLevel == PROTECTION_DANGEROUS:  # 1:"dangerous"
			dangerous_custom_permissions.append(name)
	if dangerous_custom_permissions:
		writer.startWriter("PERMISSION_DANGEROUS", LEVEL_HIGH, VUL_PERMISSION_DANGEROUS['name'],
						   VUL_PERMISSION_DANGEROUS['desc'], VUL_PERMISSION_DANGEROUS['fix'])
		for class_name in dangerous_custom_permissions:
			writer.write(class_name)
			who_use_this_permission = get_all_components_by_permission(a.get_AndroidManifest(), class_name)
			who_use_this_permission = collections.OrderedDict(sorted(who_use_this_permission.items()))
			if who_use_this_permission:
				for key, valuelist in who_use_this_permission.items():
					for list_item in valuelist:
						writer.write("    -> used by (" + key + ") " + a.format_value(list_item))
	# AndroidManifest Exported Lost Prefix Checking
	list_lost_exported_components = []
	find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
	xml = a.get_AndroidManifest()
	for tag in find_tags:
		for item in xml.getElementsByTagName(tag):
			name = item.getAttribute("android:name")
			exported = item.getAttribute("exported")
			if (not isNullOrEmptyString(name)) and (not isNullOrEmptyString(exported)):
				list_lost_exported_components.append((tag, name))
	if list_lost_exported_components:
		writer.startWriter("PERMISSION_NO_PREFIX_EXPORTED", VUL_PERMISSION_NO_PREFIX_EXPORTED['level'], VUL_PERMISSION_NO_PREFIX_EXPORTED['name'],
						   VUL_PERMISSION_NO_PREFIX_EXPORTED['desc'], VUL_PERMISSION_NO_PREFIX_EXPORTED['fix'])
		for tag, name in list_lost_exported_components:
			writer.write(("%10s => %s") % (tag, a.format_value(name)))
	return PermissionName_to_ProtectionLevel


def check_VUL_DEBUGGABLE(a, writer):
	is_debug_open = a.is_debuggable()  # Check 'android:debuggable'
	if is_debug_open:
		writer.startWriter("DEBUGGABLE", VUL_DEBUGGABLE['level'], VUL_DEBUGGABLE['name'],
						   VUL_DEBUGGABLE['desc'], VUL_DEBUGGABLE['fix'], ["Debug"])


def check_VUL_SSL_URLS_NOT_IN_HTTPS(allurls_strip_non_duplicated_final, efficientStringSearchEngine, filteringEngine,
									writer):
	allurls_strip_non_duplicated_final_prerun_count = 0
	for url in allurls_strip_non_duplicated_final:
		dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
			url)
		if filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
			allurls_strip_non_duplicated_final_prerun_count = allurls_strip_non_duplicated_final_prerun_count + 1
	if allurls_strip_non_duplicated_final_prerun_count != 0:
		writer.startWriter("SSL_URLS_NOT_IN_HTTPS", VUL_SSL_URLS_NOT_IN_HTTPS['level'], VUL_SSL_URLS_NOT_IN_HTTPS['name'],
						   "未使用HTTPs的URL (共:" + str(allurls_strip_non_duplicated_final_prerun_count) + "):",
						   VUL_SSL_URLS_NOT_IN_HTTPS['fix'], ["SSL_Security"])

		for url in allurls_strip_non_duplicated_final:  # 遍历url
			dict_class_to_method_mapping = efficientStringSearchEngine.get_search_result_dict_key_classname_value_methodlist_by_match_id(
				url)
			if not filteringEngine.is_all_of_key_class_in_dict_not_in_exclusion(dict_class_to_method_mapping):
				continue
			# 打印出url
			writer.write(url)
			try:
				if dict_class_to_method_mapping:  # 找出与url相关的代码所在
					for _, result_method_list in dict_class_to_method_mapping.items():
						for result_method in result_method_list:  # strip duplicated item
							if filteringEngine.is_class_name_not_in_exclusion(result_method.get_class_name()):
								source_classes_and_functions = (
											result_method.get_class_name() + "->" + result_method.get_name() + result_method.get_descriptor())
								writer.write("    => " + source_classes_and_functions)

			except KeyError:
				pass


def init_line_max_by_platform(args):
	# 根据不同的平台（Windows/Linux） 设置每行最大输出字符数
	if args.line_max_output_characters is None:
		if platform.system().lower() == "windows":
			args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_WINDOWS - LINE_MAX_OUTPUT_INDENT
		else:
			args.line_max_output_characters = LINE_MAX_OUTPUT_CHARACTERS_LINUX - LINE_MAX_OUTPUT_INDENT
	if not os.path.isdir(args.report_output_dir):
		os.mkdir(args.report_output_dir)


def get_output_filename(writer):
	# 包名 + "_" + 签名 + ".txt"
	package_name =  writer.getHeader("package_name")   #提取出"包名"
	signature_unique_analyze =  writer.getHeader("signature_unique_analyze")  #提取出签名
        file_path = os.path.dirname(__file__)
        print(file_path)
        file_path2 = os.path.join(file_path, DIRECTORY_REPORT_OUTPUT)
        print(file_path2)
        if not os.path.isdir(file_path2):
            os.mkdir(file_path2)
	f_name = os.path.join(file_path2, package_name + "_" + signature_unique_analyze + ".txt")
	return f_name

def __persist_file(writer, p_f_name) :
	if p_f_name:
		return writer.save_result_to_file(p_f_name)
	else :
		print("[!] 待写入文件不存在")
		return False


def main(p_apk_file) :
	writer = Writer()

	try :
		# 进入分析的核心代码
		__analyze(writer, p_apk_file)
                print("分析完成")
		analyze_signature = get_hash_scanning(writer)
		writer.writeHeader_ForceNoPrint("signature_unique_analyze", analyze_signature)	#For uniquely distinguish the analysis report
		writer.append_to_file_io_information_output_list("------------------------------------------------------------------------------------------------")

	except ExpectedException:
		writer.update_analyze_status("fail")
	except BadZipfile:	#This may happen in the "a = apk.APK(apk_Path)"
		writer.update_analyze_status("fail")
	except Exception:
		writer.update_analyze_status("fail")

	if writer.get_analyze_status() == "success" :
		out_txt = get_output_filename(writer)
		if REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_PRINT :#报告只输出到终端
			writer.show()
		elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE :#报告写入.txt文件
			__persist_file(writer, out_txt)
		elif REPORT_OUTPUT == TYPE_REPORT_OUTPUT_PRINT_AND_FILE :# 默认是既输出到终端也写入到文件
			writer.show()
			__persist_file(writer, out_txt)      # 写入txt文件
		return out_txt


if __name__ == "__main__":
	args = parse_argument()
	print args.apk_file
	out_file = main(args.apk_file)
	print(out_file)
