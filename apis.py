import pykd 
import sys
import os
import time
import ConfigParser
import _winreg
import pefile
import peutils
import random
import hashlib
import struct
import math
import binascii
import traceback
import re
import subprocess
from utils import *
from output import Results
utilsClass = Utils()
from random import randint

class Apis:
	def  __init__(self):
		self.find_data_structure_addr = 0
		self.pe_data_structure_addr = 0
		self.last_found_file = ''
		self.last_found_process = ''
		self.process_information_struct = ''
		self.last_created_process_name_args = ''
		self.api_logger = None
		self.mainClass = None
		self.prev_api = ''
		self.unpacking_apis = ["WriteFile","Sleep","GetProcAddress","Alloc_Execution","VirtualProtect","VirtualAlloc"]
		self.anti_debug_apis = ["FindWindow", "QueryInformationProcess", "ZwSetInformationThread", "TickCount", "DebugString", "QueryObject", "bugActiveProcess", "ZwContinue", "PerformanceCounter", "ConsoleCtrlEvent", "entry_address", "BlockInput"]
		self.md5 = None
	def monitor_sub_process(self,new_process_name,args):
		try:
			command =  '"' + self.mainClass.paths["cdb_path"] + '"' + " -c " + '"' + ".load pykd;!py " + self.mainClass.working_dir_path + "arena.py " + new_process_name + " " + args + " " +'" ' + new_process_name
			subprocess.call(command,shell=False)
		except Exception as e:
			print "Exception in monitor_sub_process:", e
	# Log parameters to json, only string paratmers are dereferenced, struct types' parameters are not logged yet, only pointer is logged
	def log_parameters(self,api,ret_addr,eip,api_name_only):
		on_ret = False
		ts = int(time.time())
		try:
			if self.mainClass.apis_dict[api_name_only] == "yes":
				on_ret = True
		except Exception as e:
			print "Exception in reading ret:",e
		if "_completed" in api:
			self.log_api_params(api_name_only)
			# flush the previous api name
			self.prev_api = ''		
			# remove one time breakpoints from bl
			bl=pykd.dbgCommand("bl")
			index_of_breakpoint=bl.find(eip)
			tmp=bl[index_of_breakpoint-8:index_of_breakpoint-3].split("\n")[1]
			pykd.dbgCommand("bc "+tmp)
			#sys.exit(1)
		elif on_ret == True:
			self.mainClass.bp_init.append(pykd.setBp(int(ret_addr,16),self.mainClass.break_hit))
			a=''
			a=pykd.dbgCommand("dd esp")
			self.mainClass.prev_stack = a
			self.mainClass.prev_addr=a.split(" ")[4]
			self.mainClass.prev_size=a.split(" ")[5]
			self.mainClass.breakpoints_info.update({ret_addr: api + "_completed"})
			self.mainClass.apis_dict.update({api +"_completed":"1"})
			
		else:
			# log parameters values to dict and save to json file
			self.log_api_params(api_name_only)
			
	
	def log_api_params(self,api_name):
		d = {}
		for i in self.mainClass.apis_dict[api_name]["parameters"].keys():
			value_type = self.mainClass.apis_dict[api_name]["parameters"][i]["type"]
			addr = utilsClass.get_parameter(int(i),"hex")
			ret = utilsClass.get_param_value(int(addr,16),value_type)
			event_name = self.mainClass.apis_dict[api_name]["parameters"][i]["name"]
			d.update({event_name:ret})
		if self.api_logger == None:
			self.api_logger = Results(self.mainClass.paths["results_dir_path"] + "\\" + self.md5 +"_log.json", self.md5)
		self.api_logger.write_to_file(api_name,d)
		
		# in case of create process hook the new process and attach dbg to it for further logging
		if "CreateProcess" in api_name:
			self.monitor_sub_process(d["lpApplicationName"],d["lpCommandLine"])
			
	def evaluate_hook(self,ret_addr,eip,api):
		api_name = ''
		print api
		# when value is required after api has completed "_completed" is appended to the api and stripped for logging in following line
		if "_completed" in api:
			api_name = api.split("_")[0]
		elif "!" in api_name:
			api_name = api.split("!")[1]
		else:
			api_name = api
		self.prev_api = api_name
		if api_name[-1] == 'W' or api_name[-1] == 'A':
			api_name = api_name[:-1]
			print "A or W found"
		self.prev_api = api_name
		if api_name in self.mainClass.apis_dict.keys():
			
			if api_name in self.anti_debug_apis:
				self.bypass_evasion(ret_addr,api,eip)
				
			elif api_name in self.unpacking_apis:
				self.keep_track_of_unpacking(ret_addr,api,eip)
			# decrease sleep time for quick trace
			elif "Sleep" in api_name:
				
				a=pykd.dbgCommand("dd esp")
				arg1=a.split("\n")[0].split(" ")[3]
				# sleep threshold to short-circuit
				if arg1 > "00001388":
					pykd.dbgCommand("ed "+hex(int(a.split("\n")[0].split(" ")[0],16)+4)+" " + "00001388" )
			# Log api parameters to json 
			self.log_parameters(api,ret_addr,eip,api_name)
		else:
			print "no hook "
	def main(self,ret_addr,eip,api,mainClass,md5):
		self.mainClass = mainClass
		self.md5 = md5
		self.evaluate_hook(ret_addr,eip,api)
	# TODO: use this function to keep track of unpacked code, pointers are already saved in the allocated_pointers which point to allocated space, use them to get unpacked code 
	def keep_track_of_unpacking(self,esp,event_name,eip):
				
		if "ProcAddress" in event_name:
			name_of_module = pykd.dbgCommand("!lmi " + esp)
			if "SysWOW64" in  name_of_module or "System32" in name_of_module:
				pass
			else:
				a=pykd.dbgCommand("dd esp")
				try:
					import_name=''
					name=''
					hmod=pykd.dbgCommand("lm a "+ a.split(" ")[3]).split("\n")[1].split(" ")[4]+".dll"
					name=pykd.dbgCommand("da "+ a.split(" ")[4])
					if len(name.split("\n")) > 2:
						for i in name.split('"'):
							if i.isalpha():
								import_name+=i
					else:
						import_name+=name.split("  ")[1].replace('"',"").strip("\n")
					import_name=import_name.strip("\n")
				except Exception as e:
					print "exception:"+str(e)
		elif "VirtualAlloc" in event_name:
			if "call_completed" in event_name:
				eax=pykd.dbgCommand("r eax").split("=")[1].strip("\n")
				self.mainClass.allocated_pointers.update({eax:self.mainClass.va_size})
				self.mainClass.va_size=0
			elif "VirtualAlloc_Execution" in event_name:
				print "Done"
				
			else:
				a=pykd.dbgCommand("dd esp")
				mem_rights=int(a.split("\n")[1].split(" ")[2],16)
				self.mainClass.va_size=int(a.split(" ")[4],16)
				if mem_rights==16 or mem_rights==32 or mem_rights==64 or mem_rights==128: #PAGE_EXECUTE*
					self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
					self.mainClass.breakpoints_info.update({esp:"VirtualAlloc_call_completed"})
			
		elif "VirtualProtect" in event_name:
			if "VirtualProtect_Execution" in event_name:
				pass
			else:
				a=pykd.dbgCommand("dd esp")
				mem_rights=int(a.split("\n")[0].split(" ")[5],16)
				addr=a.split("\n")[0].split(" ")[3]
				
				if mem_rights==16 or mem_rights==32 or mem_rights==64 or mem_rights==128: #PAGE_EXECUTE*
					size=a.split("\n")[0].split(" ")[4]
					print "Execute rights in VirtualProtect"
					self.mainClass.allocated_pointers.update({addr:int(size,16)})
	
	# Anti-Debugging techniques are bypassed this function
	def bypass_evasion(self,esp,event_name,eip):
		try:
			if "FindWindow" in event_name:
				a=''
				a=pykd.dbgCommand("dd esp")
				addr=a.split(" ")[4]
				esp_addr=a.split(" ")[0]
				a=pykd.dbgCommand("db "+ addr).split("  ")[2]
				if "windbg" in a.replace(".",''):
					pykd.dbgCommand("ed  "+ hex(int(esp_addr,16)+8) + " " + esp_addr)
				
			elif "QueryInformationProcess" in event_name:
				a=''
				a=pykd.dbgCommand("dd esp")
				#print a
				addr=a.split(" ")[4]
				esp_addr=a.split(" ")[0]
				if int(addr,16)==7 or int(addr,16)==30 or int(addr,16)==31 :
					pykd.dbgCommand("ed  "+ hex(int(esp_addr,16)+4) + " " + "0")
				a=pykd.dbgCommand("dd esp")
				addr=a.split(" ")[4]
				esp_addr=a.split(" ")[0]
				a=pykd.dbgCommand("dd esp+8").split("  ")[1][:8]
				
				if int(addr,16) == 17:
					pykd.dbgCommand("ed  "+ hex(int(esp_addr,16)+4) + " " + "0")
				if "call_completed" in event_name:
					if self.mainClass.previous_tick_count == 0:
						self.mainClass.previous_tick_count=int("9378c867",16)
						pykd.dbgCommand("r @eax=9378c867")#+ hex(int("9378c867",16))[2:-1])
					else:
						pykd.dbgCommand("r @eax="+ hex(self.mainClass.previous_tick_count+2)[2:-1])
						self.mainClass.previous_tick_count=int(pykd.dbgCommand("r eax").split("=")[1].strip("\n"),16)
					bl=pykd.dbgCommand("bl")
					index_of_breakpoint=bl.find(eip)
					tmp=bl[index_of_breakpoint-8:index_of_breakpoint-3].split("\n")[1]
					pykd.dbgCommand("bc "+tmp)
				else:
					if esp in self.mainClass.breakpoints_info.keys():
						pass
					else:
						self.mainClass.GetTickCount_call_count += 1
						self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
						self.mainClass.breakpoints_info.update({esp:"GetTickCount_call_completed"})
				
			elif "DebugString" in event_name:
				if "DebugString_call_completed" in event_name:
					
					pykd.dbgCommand("r @eax=1")
					teb=pykd.dbgCommand("r $teb").split("=")[1].strip("\n")
					pykd.dbgCommand("ed "+  hex(int(teb,16)+52)[2:] + " 6")
				else:
					self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
					self.mainClass.breakpoints_info.update({esp:"OutputDebugString_call_completed"})
			elif "QueryObject" in event_name:
				
				if "QueryObject_call_completed" in event_name:
					pykd.dbgCommand("ed "+ hex(self.mainClass.pObjectAllInfo)+ " 0")
				else:
					a=pykd.dbgCommand("dd esp")
					addr=a.split("\n")[0].split(" ")[5]
					self.mainClass.pObjectAllInfo=int(addr,16)
					self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
					self.mainClass.breakpoints_info.update({esp:"NtQueryObject_call_completed"})
					
			elif "DebugActiveProcess" in event_name:
				if "bugActiveProcess_call_completed" in event_name:
					pykd.dbgCommand("r @eax=1")
				else:
					self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
					self.mainClass.breakpoints_info.update({esp:"DebugActiveProcess_call_completed"})
			elif "ZwContinue" in event_name:
				pass
				if "_call_completed" in event_name:
					pass
				else:
					a=pykd.dbgCommand("dd esp")
					addr=a.split("\n")[0].split(" ")[3]
					next_eip=pykd.dbgCommand("dd "+hex(int(addr,16)+int("b8",16))[2:]).split("\n")[0].split(" ")[2]
			elif "PerformanceCounter" in event_name:
				if "PerformanceCounter_call_completed" in event_name:
					pykd.dbgCommand("eq "+ hex(self.mainClass.pLarge_integer)+ " 0")
				else:
					self.mainClass.QueryPerformanceCounter_call_count +=1
					a=pykd.dbgCommand("dd esp")
					addr=a.split("\n")[0].split(" ")[3]
					self.mainClass.pLarge_integer=int(addr,16)
					self.mainClass.bp_init.append(pykd.setBp(int(esp,16),self.mainClass.break_hit))
					self.mainClass.breakpoints_info.update({esp:"QueryPerformanceCounter_call_completed"})# +=esp+" "+ "QueryPerformanceCounter_call_completed" +"\n"
				
			
			elif "ConsoleCtrlEvent" in event_name:
				esp_addr=pykd.dbgCommand("r esp").split("=")[1].strip("\n")
				event=int(pykd.dbgCommand("dd "+ esp_addr).split("\n")[0].split(" ")[3],16)
				
				if event==0:
					pykd.dbgCommand("ed "+ hex(int(esp_addr,16)+4)[2:] + " 10")
			elif "entry_address" in event_name:
				teb=pykd.dbgCommand("r $teb").split("=")[1].strip("\n")
				a=pykd.dbgCommand("dd "+  hex(int(teb,16)+int("1000",16)+24)[2:]).split("\n")[0].split(" ")[2]
				pykd.dbgCommand("ba r4 "+  hex(int(a,16)+16) +'"' + "r @eax=0;gc"+'"' )
				pykd.dbgCommand("ba r4 "+  hex(int(a,16)+12) +'"' + "r @eax=2;gc"+'"' )
			elif "BlockInput" in event_name:
				esp_addr=pykd.dbgCommand("r esp").split("=")[1].strip("\n")
				event=int(pykd.dbgCommand("dd "+hex(int(esp_addr,16)+4)[2:]).split("\n")[0].split(" ")[2],16)
				if event==1:
					pykd.dbgCommand("ed "+ hex(int(esp_addr,16)+4)[2:] + " 0")
			else:
				print "skipping"
		except Exception as e:
			print "exception in bypass: " + str(e)
			
		return True