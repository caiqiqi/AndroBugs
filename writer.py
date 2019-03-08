#coding=utf-8
import os
from textwrap import TextWrapper   #for indent in output
import collections	#for sorting key of dictionary
import json

from tools.modified.androguard.core.analysis import analysis

from constant import *


class Writer:
	def __init__(self) :
		self.__package_information = {}
		self.__cache_output_detail_stream = []
		self.__output_dict_vector_result_information = {}		# Store the result information (key: tag ; value: name,level,desc,detail,fix)
		self.__output_current_tag = ""					#The current vector analyzed

		self.__file_io_result_output_list = []			#分析报告漏洞结果
		self.__file_io_header_output_list = []		    #分析报告头(包括package_name, md5, sha1等)

		self.__sorted_output_dict_result_information  = collections.OrderedDict()
		self.__is_sorted_output_dict_result_information = False

	def simplify_class_path(self, class_name) :
		if class_name.startswith('L') and class_name.endswith(';'):
			return class_name[1:-1]
		return class_name

	def show_path(self, vm, path, indention_space_count=0) :
		"""
			Different from analysis.show_Path, this "show_Path" writes to the tmp writer 
		"""

		cm = vm.get_class_manager()

		if isinstance(path, analysis.PathVar):
			dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
			info_var = path.get_var_info()

			self.write("=> %s (0x%x) ---> %s->%s%s" % (info_var,
													path.get_idx(),
													dst_class_name,
													dst_method_name,
													dst_descriptor),
				indention_space_count)

		else :
			if path.get_access_flag() == analysis.TAINTED_PACKAGE_CALL :
				src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
				dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

				self.write("=> %s->%s%s (0x%x) ---> %s->%s%s" % (src_class_name,
																src_method_name,
																src_descriptor,
																path.get_idx(),
																dst_class_name,
																dst_method_name,
																dst_descriptor),
					indention_space_count)

			else :
				src_class_name, src_method_name, src_descriptor =  path.get_src( cm )

				self.write("=> %s->%s%s (0x%x)" % (src_class_name,
												src_method_name,
												src_descriptor,
												path.get_idx()),
					indention_space_count)

	def show_path_only_source(self, vm, path, indention_space_count=0) :
		cm = vm.get_class_manager()
		src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
		self.write("=> %s->%s%s" % (src_class_name, src_method_name, src_descriptor), indention_space_count)		

	def show_paths(self, vm, paths, indention_space_count=0) :
		"""
			Show paths of packages
			:param paths: a list of :class:`PathP` objects

			Different from "analysis.show_Paths", this "show_Paths" writes to the tmp writer 
		"""
		for path in paths :
			self.show_path(vm, path, indention_space_count)

	def show_single_PathVariable(self, vm, path, indention_space_count=0):
		"""
			Different from "analysis.show_single_PathVariable", this "show_single_PathVariable" writes to the tmp writer 

			method[0] : class name
			method[1] : function name
			method[2][0] + method[2][1]) : description
		"""
		access, idx = path[0]
		m_idx = path[1]
		method = vm.get_cm_method(m_idx)

		self.write("=> %s->%s %s" % (method[0], method[1], method[2][0] + method[2][1]),	indention_space_count)

	def startWriter(self, tag, level, name, desc, fix, special_tag=None, cve_number="") :	
		"""
			"tag" is for internal usage
			"level, name, desc, special_tag, cve_number" will be shown to the users
			It will be sorted by the "tag". The result will be sorted by the "tag".

			Notice: the type of "special_tag" is "list"
		"""
		self.completeWriter()
		self.__output_current_tag = tag

		assert ((tag is not None) and (level is not None) and (name is not None) and (desc is not None)), "\"tag\", \"level\", \"name\", \"desc\" should all have it's value."

		if tag not in self.__output_dict_vector_result_information :
			self.__output_dict_vector_result_information[tag] = []

		dict_tmp_information = dict()
		dict_tmp_information["tag"] = tag
		dict_tmp_information["level"] = level
		dict_tmp_information["desc"] = desc.rstrip('\n')
		dict_tmp_information["fix"] = fix
		dict_tmp_information["name"] = name.rstrip('\n')
		dict_tmp_information["count"] = 0
		if special_tag :
			assert isinstance(special_tag, list), "Tag [" + tag + "] : special_tag should be list"
		if cve_number :
			assert isinstance(cve_number, basestring), "Tag [" + tag + "] : special_tag should be string"

		self.__output_dict_vector_result_information[tag] = dict_tmp_information
		
	def get_valid_encoding_utf8_string(self, utf8_string) :
		return utf8_string.decode('unicode-escape').encode('utf8')

	def write(self, detail_msg, indention_space_count=0) :
		self.__cache_output_detail_stream.append(detail_msg + "\n")

	def get_packed_analyzed_results_for_mongodb(self) :
		analyze_packed_result = self.getHeader()

		if analyze_packed_result :
			if self.get_analyze_status() == "success" :
				analyze_packed_result["details"] = self.__output_dict_vector_result_information
			return analyze_packed_result

		return None

	def get_search_enhanced_packed_analyzed_results_for_mongodb(self) :
		# For external storage

		analyze_packed_result = self.getHeader()

		if analyze_packed_result :
			if self.get_analyze_status() == "success" :

				prepared_search_enhanced_result = []

				for tag, dict_information in self.__output_dict_vector_result_information.items() :

					search_enhanced_result = dict()

					search_enhanced_result["vector"] = tag
					search_enhanced_result["level"] = dict_information["level"]
					search_enhanced_result["analyze_engine_build"] = analyze_packed_result["analyze_engine_build"]
					search_enhanced_result["analyze_mode"] = analyze_packed_result["analyze_mode"]
					if "analyze_tag" in analyze_packed_result :
						search_enhanced_result["analyze_tag"] = analyze_packed_result["analyze_tag"]
					search_enhanced_result["package_name"] = analyze_packed_result["package_name"]
					if "package_version_code" in analyze_packed_result :
						search_enhanced_result["package_version_code"] = analyze_packed_result["package_version_code"]
					search_enhanced_result["file_sha512"] = analyze_packed_result["file_sha512"]
					search_enhanced_result["signature_unique_analyze"] = analyze_packed_result["signature_unique_analyze"]
					
					prepared_search_enhanced_result.append(search_enhanced_result)

				return prepared_search_enhanced_result

		return None

	def getHeader(self, key=None, default_value=None) :
		if key is None :
			return self.__package_information

		if key in self.__package_information :    
			value = self.__package_information[key]
			if (value is None) and (default_value is not None) :    # [Important] if default_value="", the result of the condition is "False"
				return default_value
			return value

		#not found
		if default_value :    # [Important] if default_value="", the result of the condition is "False"
			return default_value

		return None

	def writePlainHeader(self, msg) :
		# if DEBUG :
		print(str(msg))
		# [Recorded here]
		self.__file_io_header_output_list.append(str(msg))

	def writeHeader(self, key, value, extra_title, extra_print_original_title=False) :
		# if DEBUG :
		if extra_print_original_title :
			print(str(extra_title))
			# [Recorded here]
			self.__file_io_header_output_list.append(str(extra_title))
		else :
			print(extra_title + ": " + str(value))
			# [Recorded here]
			self.__file_io_header_output_list.append(extra_title + ": " + str(value))

		self.__package_information[key] = value

	def writeHeader_ForceNoPrint(self, key, value) :
		self.__package_information[key] = value

	def update_analyze_status(self, status) :
		self.writeHeader_ForceNoPrint("analyze_status", status)

	def get_analyze_status(self) :
		return self.getHeader("analyze_status")

	def get_total_vector_count(self) :   #得到这次漏洞分析的漏洞总数
		if self.__output_dict_vector_result_information :
			return len(self.__output_dict_vector_result_information)
		return 0

	def completeWriter(self) :
		# save to DB
		if (self.__cache_output_detail_stream) and (self.__output_current_tag != "") :   
			#This is the preferred way if you know that your variable is a string. If your variable could also be some other type then you should use myString == ""
			
			current_tag = self.__output_current_tag
			# try :
			if current_tag in self.__output_dict_vector_result_information :
				self.__output_dict_vector_result_information[current_tag]["count"] = len(self.__cache_output_detail_stream)

				"""
					Use xxx.encode('string_escape') to avoid translating user code into command
					For example: regex in the code of users' applications may include "\n" but you should escape it.

					I add "str(xxx)" because the "xxx" of xxx.encode should be string but "line" is not string.
					Now the desc and detail of the vectors are escaped(\n,...), so you need to use "get_valid_encoding_utf8_string"

					[String Escape Example] 
					http://stackoverflow.com/questions/6867588/how-to-convert-escaped-characters-in-python
					>>> escaped_str = 'One \\\'example\\\''
					>>> print escaped_str.encode('string_escape')
					One \\\'example\\\'
					>>> print escaped_str.decode('string_escape')
					One 'example'
				"""

				output_string = ""
				for line in self.__cache_output_detail_stream :
					output_string = output_string + str(line).encode('string_escape')	# To escape the "\n" shown in the original string inside the APK

				self.__output_dict_vector_result_information[current_tag]["details"] = self.get_valid_encoding_utf8_string(output_string.rstrip(str('\n').encode('string_escape')))
#				self.__output_dict_vector_result_information[current_tag]["details"] = output_string.rstrip(str('\n').encode('string_escape'))
				try :
					pass #self.__output_dict_vector_result_information[current_tag]["desc"] = self.get_valid_encoding_utf8_string(self.__output_dict_vector_result_information[current_tag]["desc"])
				except KeyError :
					if DEBUG:
						print("[KeyError on \"self.__output_dict_vector_result_information\"]")
					pass


		self.__output_current_tag = ""
		self.__cache_output_detail_stream[:] = []	# Clear the items in the list

	def is_dict_information_has_cve_number(self, dict_information) :  #是否有CVE编号
		if dict_information :
			if "cve_number" in dict_information :
				return True
		return False

	def is_dict_information_has_special_tag(self, dict_information) :  #是否有特殊标志
		if dict_information :
			if "special_tag" in dict_information :
				if dict_information["special_tag"] :
					return True
		return False

	def __sort_by_level(key, value):
		try :
			level = value[1]["level"]

			if level == LEVEL_HIGH:
				return 5
			elif level == LEVEL_MEDIUM:
				return 4
			elif level == LEVEL_LOW:
				return 3
			elif level == LEVEL_INFO:
				return 2
			else:
				return 1
		except KeyError :
			return 1

	def append_to_file_io_information_output_list(self, line) :
		# Only write to the header of the "external" file
		self.__file_io_header_output_list.append(line)

	def save_result_to_file(self, output_file_path) :
		if not self.__file_io_result_output_list :
			self.load_to_output_list()

		self.save_result_to_json_file(output_file_path + ".json")  #将结果写入json文件
		try :
			with open(output_file_path, "w") as f :
				if self.__file_io_header_output_list :
					for line in self.__file_io_header_output_list :   #逐行取出Header的内容，写到文件中
						f.write(line + "\n")
				for line in self.__file_io_result_output_list :            #逐行取出Result的内容，写到文件中
					f.write(line + "\n")


			print("<<< 分析报告已生成: " + os.path.abspath(output_file_path) + " >>>")
			print("")

			return True
		except IOError as err:
			if DEBUG :
				print("[Error on writing output file to disk]")
			return False

	def save_result_to_json_file(self, output_json_file_path) :
		#Dict to json
		#print(json.dumps(sorted_output_dict_result_information))
		if self.__is_sorted_output_dict_result_information:
			with open(output_json_file_path, 'w') as fp:
				json.dump(self.__sorted_output_dict_result_information, fp, indent=4, ensure_ascii=False)

	def show(self) :
		if not self.__file_io_result_output_list :
			self.load_to_output_list()

		if self.__file_io_result_output_list :
			for line in self.__file_io_result_output_list :  #直接逐行输出
				print(line)

	def output(self, line) :	#Store here for later use on "print()" or "with ... open ..."
		self.__file_io_result_output_list.append(line)

	def output_and_force_print_console(self, line) :	#Store here for later use on "print()" or "with ... open ..."
		# [Recorded here]
		self.__file_io_result_output_list.append(line)
		print(line)

	def sort_output_dict_result_information(self, output_dict_vector_result_information):
		return collections.OrderedDict(sorted(output_dict_vector_result_information.items()))	#Sort the dictionary by key

	def load_to_output_list(self) :
		self.__file_io_result_output_list[:] = []	#clear the list
        # 设置“漏洞标题”和“漏洞描述”每行的字数，以及缩进量
		wrapperTitle = TextWrapper(initial_indent=' ' * 11, subsequent_indent=' ' * 11, width=LINE_MAX_OUTPUT_CHARACTERS_LINUX-LINE_MAX_OUTPUT_INDENT)
		wrapperDetail = TextWrapper(initial_indent=' ' * 15, subsequent_indent=' ' * 20, width=LINE_MAX_OUTPUT_CHARACTERS_LINUX-LINE_MAX_OUTPUT_INDENT)

		self.__sorted_output_dict_result_information = self.sort_output_dict_result_information(self.__output_dict_vector_result_information)
		self.__is_sorted_output_dict_result_information = True

		for tag, dict_information in sorted(self.__sorted_output_dict_result_information.items(), key=self.__sort_by_level, reverse=True) :	#Output the sorted dictionary by level
			self.output("[%s] %s:" % (dict_information["level"],  dict_information["name"]))

			for line in dict_information["desc"].split('\n') :
				self.output(wrapperTitle.fill(line))

			if "details" in dict_information :
				for line in dict_information["details"].split('\n'):
					self.output(wrapperDetail.fill(line))

		self.output("------------------------------------------------------------")

		stopwatch_total_elapsed_time = self.getHeader("time_total")
		stopwatch_analyze_time = self.getHeader("time_analyze")
		stopwatch_loading_vm_time = self.getHeader("time_loading_vm")
		if stopwatch_total_elapsed_time and stopwatch_analyze_time :

			if (REPORT_OUTPUT == TYPE_REPORT_OUTPUT_ONLY_FILE) :
				self.output_and_force_print_console("AndroBugs分析用时: " + str(stopwatch_analyze_time) + " 秒")
				self.output_and_force_print_console("载入VM用时: " + str(stopwatch_loading_vm_time) + " 秒")
				self.output_and_force_print_console("总耗时: " + str(stopwatch_total_elapsed_time) + " 秒")
			else:
				self.output("AndroBugs分析用时: " + str(stopwatch_analyze_time) + " 秒")
				self.output("载入VM用时: " + str(stopwatch_loading_vm_time) + " 秒")
				self.output("总耗时: " + str(stopwatch_total_elapsed_time) + " 秒")