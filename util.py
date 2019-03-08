#coding=utf-8
import re
import time
import random
import hashlib    #sha256 hash

from constant import *


# 据说是一个高效的字符串搜索引擎
class EfficientStringSearchEngine :

	"""
		Usage:
			1.create an EfficientStringSearchEngine instance (只需要一个)
			2.addSearchItem
			3.search
			4.get_search_result_by_match_id or get_search_result_dict_key_classname_value_methodlist_by_match_id
	"""

	def __init__(self) :
		self.__prog_list = []
		self.__dict_result_identifier_to_search_result_list = {}

	def add_search_item(self, match_id, search_regex_or_fix_string_condition, isRegex) :
		self.__prog_list.append( (match_id, search_regex_or_fix_string_condition, isRegex) )

	def search(self, vm, allstrings_list) :

		"""
			Example prog list input:
				[ ("match1", re.compile("PRAGMA\s*key\s*=", re.I), True), ("match2", re.compile("/system/bin/"), True), ("match3", "/system/bin/", False) ]

			Example return (Will always return the corresponding key, but the value is return only when getting the result):
				{ "match1": [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] , "match2": [] }
		"""

		self.__dict_result_identifier_to_search_result_list.clear()

		for identifier, _ , _ in self.__prog_list :	#initializing the return result list
			if identifier not in self.__dict_result_identifier_to_search_result_list :
				self.__dict_result_identifier_to_search_result_list[identifier] = []

		dict_string_value_to_idx_from_file_mapping = {}

		for idx_from_file, string_value in vm.get_all_offset_from_file_and_string_value_mapping() :	#get a dictionary of string value and string idx mapping
			dict_string_value_to_idx_from_file_mapping[string_value] = idx_from_file

		list_strings_idx_to_find = []	#string idx list
		dict_string_idx_to_identifier = {}   # Example: (52368, "match1")

		#Get the searched strings into search idxs
		for line in allstrings_list :
			for identifier, regexp, isRegex in self.__prog_list :
				if (isRegex and regexp.search(line)) or ((not isRegex) and (regexp == line)) :
					if line in dict_string_value_to_idx_from_file_mapping :   #Find idx by string
						string_idx = dict_string_value_to_idx_from_file_mapping[line]
						list_strings_idx_to_find.append(string_idx)
						dict_string_idx_to_identifier[string_idx] = identifier

		list_strings_idx_to_find = set(list_strings_idx_to_find)	#strip duplicated items

		if list_strings_idx_to_find :
			cm = vm.get_class_manager()
			for method in vm.get_methods() :  # 得到这个dex的所有方法
				for i in method.get_instructions():   # 得到某个方法的所有指令
					if (i.get_op_value() == 0x1A) or (i.get_op_value() == 0x1B) :  # 0x1A = "const-string", 0x1B = "const-string/jumbo"
						ref_kind_idx = cm.get_offset_idx_by_from_file_top_idx(i.get_ref_kind())
						if ref_kind_idx in list_strings_idx_to_find :  #find string_idx in string_idx_list
							if ref_kind_idx in dict_string_idx_to_identifier :
								original_identifier_name = dict_string_idx_to_identifier[ref_kind_idx]
								self.__dict_result_identifier_to_search_result_list[original_identifier_name].append( (i.get_string(), method) )

		return self.__dict_result_identifier_to_search_result_list

	def get_search_result_by_match_id(self, match_id):
		return self.__dict_result_identifier_to_search_result_list[match_id]

	def get_search_result_dict_key_classname_value_methodlist_by_match_id(self, match_id):
		"""
			Input: [ (Complete_String_found, EncoddedMethod), (Complete_String_found, EncoddedMethod) ] or []
			Output: dicionary key by class name
		"""
		dict_result = {}

		search_result_value = self.__dict_result_identifier_to_search_result_list[match_id]

		try :
			if search_result_value :  #Found the corresponding url in the code
				result_list = set(search_result_value)

				for _ , result_method in result_list :  #strip duplicated item
					class_name = result_method.get_class_name()
					if class_name not in dict_result :
						dict_result[class_name] = []

					dict_result[class_name].append(result_method)
		except KeyError:
			pass

		return dict_result


class FilteringEngine :
	def __init__(self, enable_exclude_classes, str_regexp_type_excluded_classes) :
		self.__enable_exclude_classes = enable_exclude_classes
		self.__str_regexp_type_excluded_classes = str_regexp_type_excluded_classes
		self.__regexp_excluded_classes = re.compile(self.__str_regexp_type_excluded_classes, re.I)

	def get_filtering_regexp(self) :
		return self.__regexp_excluded_classes

	def filter_efficient_search_result_value(self, result) :

		if result is None :
			return []
		if (not self.__enable_exclude_classes) :
			return result

		l = []
		for found_string, method in result :
			if not self.__regexp_excluded_classes.match(method.get_class_name()) :
				l.append( (found_string, method) )

		return l

	def is_class_name_not_in_exclusion(self, class_name) :
		if self.__enable_exclude_classes :
			if self.__regexp_excluded_classes.match(class_name) :
				return False
			else :
				return True
		else :
			return True

	def is_all_of_key_class_in_dict_not_in_exclusion(self, dict_result) :
		if self.__enable_exclude_classes :
			isAllMatchExclusion = True
			for class_name, method_list in dict_result.items() :
				if not self.__regexp_excluded_classes.match(class_name) :	#any match
					isAllMatchExclusion = False
			
			if isAllMatchExclusion :
				return False

			return True
		else :
			return True

	def filter_list_of_methods(self, method_list) :
		"""
		过滤出排除类型之外类的类方法
		"""
		if self.__enable_exclude_classes and method_list :
			l = []
			for method in method_list :
				if not self.__regexp_excluded_classes.match(method.get_class_name()) :
					l.append(method)
			return l
		else :
			return method_list

	def filter_list_of_classes(self, class_list) :
		"""
		过滤出排除类型之外类的类
		"""
		if self.__enable_exclude_classes and class_list :
			l = []
			for i in class_list :
				if not self.__regexp_excluded_classes.match(i) :
					l.append(i)
			return l
		else :
			return class_list

	def filter_list_of_paths(self, vm, paths):
		if self.__enable_exclude_classes and paths :
			cm = vm.get_class_manager()

			l = []
			for path in paths :
				src_class_name, src_method_name, src_descriptor =  path.get_src(cm)
				if not self.__regexp_excluded_classes.match(src_class_name) :
					l.append(path)

			return l
		else :
			return paths

	def filter_dst_class_in_paths(self, vm, paths, excluded_class_list):
		cm = vm.get_class_manager()

		l = []
		for path in paths :
			dst_class_name, _, _ =  path.get_dst(cm)
			if dst_class_name not in excluded_class_list :
				l.append(path)

		return l

	def filter_list_of_variables(self, vm, paths) :
		"""
			Example paths input: [[('R', 8), 5050], [('R', 24), 5046]]
		"""

		if self.__enable_exclude_classes and paths :
			l = []
			for path in paths :
				access, idx = path[0]
				m_idx = path[1]
				method = vm.get_cm_method(m_idx)
				class_name = method[0]

				if not self.__regexp_excluded_classes.match(class_name) :
					l.append(path)
			return l
		else :
			return paths

	def get_class_container_dict_by_new_instance_classname_in_paths(self, vm, analysis, paths, result_idx):   #dic: key=>class_name, value=>paths
		dic_classname_to_paths = {}
		paths = self.filter_list_of_paths(vm, paths)
		for i in analysis.trace_Register_value_by_Param_in_source_Paths(vm, paths):
			if (i.getResult()[result_idx] is None) or (not i.is_class_container(result_idx)) :  #If parameter 0 is a class_container type (ex: Lclass/name;)
				continue
			class_container = i.getResult()[result_idx]
			class_name = class_container.get_class_name()
			if class_name not in dic_classname_to_paths:
				dic_classname_to_paths[class_name] = []
			dic_classname_to_paths[class_name].append(i.getPath())
		return dic_classname_to_paths


class ExpectedException(Exception) :
	def __init__(self, err_id, message):
		self.err_id = err_id
		self.message = message
	def __str__(self):
		return "[" + self.err_id + "] " + self.message

	def get_err_id(self) :
		return self.err_id

	def get_err_message(self) :
		return self.message


class StringHandler :
	def __init__(self, initial_str="") :
		self.str = initial_str

	def __repr__(self) :
		return self.str

	def __str__(self) :
		return self.str

	def append(self, new_string) :
		self.str += new_string

	def appendNewLine(self) :
		self.str += "\n"

	def get(self) :
		return self.str


def toNdkFileFormat(name):
	return "lib" + name + ".so"


def get_protectionLevel_string_by_protection_value_number(num) :
	if num == PROTECTION_NORMAL :
		return "normal"
	elif num == PROTECTION_DANGEROUS :
		return "dangerous"
	elif num == PROTECTION_SIGNATURE :
		return "signature"
	elif num == PROTECTION_SIGNATURE_OR_SYSTEM :
		return "signatureOrSystem"
	else :
		return num


def isBase64(base64_string):
		return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', base64_string)


def isSuccessBase64DecodedString(base64_string):
	# Punct: \:;/-.,?=<>+_()[]{}|"'~`*
	return re.match('^[A-Za-z0-9\\\:\;\/\-\.\,\?\=\<\>\+\_\(\)\[\]\{\}\|\"\'\~\`\*]+$', base64_string)


def isNullOrEmptyString(input_string, strip_whitespaces=False):
	if input_string is None :
		return True
	if strip_whitespaces :
		if input_string.strip() == "" :
			return True
	else :
		if input_string == "" :
			return True
	return False


def dump_NDK_library_classname_to_ndkso_mapping_ndk_location_list(list_NDK_library_classname_to_ndkso_mapping) :
	l = []
	for ndk_location , path in list_NDK_library_classname_to_ndkso_mapping:
		l.append(ndk_location)
	return l


def get_hashes_by_filename(filename):
	"""
	获取某文件的hash值
	"""
	md5 = None
	sha1 = None
	sha256 = None
	with open(filename) as f:
		data = f.read()    
		md5 = hashlib.md5(data).hexdigest()
		sha1 = hashlib.sha1(data).hexdigest()
		sha256 = hashlib.sha256(data).hexdigest()
	return md5, sha1, sha256

def get_sha1_by_filename(filename):
    sha1 = None
    with open(filename) as f:
        data = f.read()
        sha1 = hashlib.sha1(data).hexdigest()
    return sha1

def get_hash_scanning(writer) :
	# use "-" because aaa-bbb.com is not a valid domain name
	tmp_original = writer.getHeader("package_name", "pkg") + "-" + writer.getHeader("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
	tmp_hash = hashlib.sha256(tmp_original).hexdigest()
	return tmp_hash


def get_hash_exception(writer) :
	tmp_original = writer.getHeader("analyze_error_id", "err") + "-" + writer.getHeader("file_sha256", "sha256") + "-" + str(time.time()) + "-" + str(random.randrange(10000000, 99999999))
	tmp_hash = hashlib.sha256(tmp_original).hexdigest()
	return tmp_hash


def is_class_implements_interface(cls, search_interfaces, compare_type):
	class_interfaces = cls.get_interfaces()
	if class_interfaces is None:
		return False
	if compare_type == TYPE_COMPARE_ALL: # All
		for i in search_interfaces:
			if i not in class_interfaces:
				return False
		return True
	elif compare_type == TYPE_COMPARE_ANY: #Any
		for i in search_interfaces:
			if i in class_interfaces:
				return True
		return False


def get_method_ins_by_superclass_and_method(vm, super_classes, method_name, method_descriptor) :
	"""
	检测某类的方法被调用
	"""
	for cls in vm.get_classes() :
		if cls.get_superclassname() in super_classes :
			for method in cls.get_methods():
				if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
					yield method


def get_method_ins_by_implement_interface_and_method(vm, implement_interface, compare_type, method_name, method_descriptor) :
	"""
		Example result:
			(Ljavax/net/ssl/HostnameVerifier; Ljava/io/Serializable;)
	"""

	for cls in vm.get_classes() :
		if is_class_implements_interface(cls, implement_interface, compare_type) :
			for method in cls.get_methods():
				if (method.get_name() == method_name) and (method.get_descriptor() == method_descriptor) :
					yield method


def get_method_ins_by_implement_interface_and_method_desc_dict(vm, implement_interface, compare_type, method_name_and_descriptor_list) :
	
	dict_result = {}

	for cls in vm.get_classes() :
		if is_class_implements_interface(cls, implement_interface, compare_type) :
			class_name = cls.get_name()
			if class_name not in dict_result :
				dict_result[class_name] = []

			for method in cls.get_methods():
				name_and_desc = method.get_name() + method.get_descriptor()
				if name_and_desc in method_name_and_descriptor_list :
					dict_result[class_name].append(method)

	return dict_result


def is_kind_string_in_ins_method(method, kind_string) :
	for ins in method.get_instructions():
		try :
			if ins.get_kind_string() == kind_string:
				return True
		except AttributeError :  # Because the instruction may not have "get_kind_string()" method
			return False
	return False


def get_all_components_by_permission(xml, permission):
	"""
	根据权限名获取组件
        Return: 
            (1) activity
            (2) activity-alias
            (3) service
            (4) receiver
            (5) provider
        who use the specific permission
    """

	find_tags = ["activity", "activity-alias", "service", "receiver", "provider"]
	dict_perms = {}

	for tag in find_tags:
		for item in xml.getElementsByTagName(tag) :
			if (item.getAttribute("android:permission") == permission) or (item.getAttribute("android:readPermission") == permission) or (item.getAttribute("android:writePermission") == permission) :
				if tag not in dict_perms :
					dict_perms[tag] = []
				dict_perms[tag].append(item.getAttribute("android:name"))
	return dict_perms
