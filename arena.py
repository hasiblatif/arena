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
import base64
import json
import shutil
import traceback
from time import sleep
from apis import *
from utils import *
import xml.etree.ElementTree as ET
from output import Results
utilsClass = Utils()

class analysis:
	def __init__(self):
		self.start_address=0
		self.end_address=0
		self.breakpoints_info= {}
		self.apis_dict = {}
		self.white_list=''
		self.late_load_apis_fh=''
		self.apisClass = Apis()
		self.late_load_api_path=''
		self.results_path = ''
		self.paths = {}
		self.loadlibray_calls_count=0
		self.no_of_imports=0
		self.allocated_pointers={"pointer":0}
		self.bp_init = []
		self.hooked_apis = []
		self.signatures_db_file=''
		self.md5=''
		self.late_load_apis = []
		self.working_dir_path = ''
		self.start_time = time.time()
		
		self.paths.update({"conf_path":"arena.conf"})
		if os.path.isfile(self.paths["conf_path"]):
			config = ConfigParser.ConfigParser()
			config.readfp(open(self.paths["conf_path"]))
			self.working_dir_path = config.get('conf','working_dir_path')
			self.paths.update({"cdb_path":config.get('conf','cdb_path')})
			self.to_hook_apis_path = self.working_dir_path + "apis_list.txt"
			self.signatures_db_file=self.working_dir_path  + "userdb2.txt"
			self.white_list=self.working_dir_path  + "white_listed_apis.txt"
			self.results_path = self.working_dir_path + "results\\"
	
	def break_hit(self):
		try:
			esp=pykd.dbgCommand("dd esp").split("\n")[0].split(" ")[2]
			eip=pykd.dbgCommand("r eip").split("=")[1].strip("\n")
			called_api=self.breakpoints_info[eip]
			# in case loadlibrary is called, put the breakpoints on hooks which could not be set before. In case of packers this technique is helpful 
			if "LoadLibrary" in called_api:
				self.loadlibray_calls_count += 1
				if self.loadlibray_calls_count > 8:
					pass
				else:
					self.loadlibrary(esp,called_api)
			event = called_api.lower()
			# A dirty hack, 60000000 and below virtual memory means hooked exe is calling an API, true most of the times 
			if int(esp,16)-6 < int("60000000",16) or "completed" in called_api:
				# Do your exiting routine here, any stuff you want
				if "ExitProcess" in called_api or "ZwTerminateProcess" in called_api:
					self.process_terminating()
				
				self.apis_stub(esp,eip,called_api)
		except Exception as e:
			print "exception in break_hit: " + str(e)
			traceback.print_exc()
	
	def apis_stub(self,esp,eip,called_api):
		if self.apisClass != None:
			self.apisClass.main(esp,eip,called_api,self,self.md5)
		
		
	def process_terminating(self):
		#TODO: If you want do something before termination
		pass
	def loadlibrary(self,esp,api):
		if "LoadLibrary_call_completed" in api:
			# some APIs are in the DLLs which are not loaded at the beginning, so at each DLL call this function is called to hook remaining APIs where applicable
			self.install_late_loaded_apis_hooks()
		else:
			self.bp_init.append(pykd.setBp(int(esp,16),self.break_hit))
			self.breakpoints_info+=esp+" "+ "LoadLibrary_call_completed" +"\n"
	
	
	def create_bps(self):
		tmp=pykd.dbgCommand("lm;")
		exe_name = ''
		try:
			exe_name=tmp.split("\n")[1].split("   ")[1].split(" ")[0]
		except Exception as e:
			print "error in exe name:" + str(e)
			sys.exit(1)
		global_counter=0
		iat_start=''
		iat = ''
		self.start_address=hex(int(tmp.split("\n")[1].split(" ")[0],16)&0xffffffff)[2:-1]
		self.end_address=hex(int(tmp.split("\n")[1].split(" ")[1],16)&0xffffffff)[2:-1]
		get_all_calls=" !dh " + exe_name 
		
		a=pykd.dbgCommand(get_all_calls)
		b=a.split("\n")
		# some exceptions are bypassed to let the exe flow. Attackers use some exceptions to halt the debugging when a debugger is attached
		pykd.dbgCommand("sxi 80000003 ")
		pykd.dbgCommand("sxi c0000005 ")
		pykd.dbgCommand("sxi c0000008 ")
		pykd.dbgCommand("sxi c0000094 ")
		pykd.dbgCommand("sxi c0000095 ") 
		pykd.dbgCommand("sxi C0000096 ")
		pykd.dbgCommand("sxi 80000001 ")
		pykd.dbgCommand("sxi 80000004 ")
		
		for i in self.hooked_apis:
			try:
				command = "x *!" + i + "*"
				x_result = pykd.dbgCommand(command)
				#print x_result
				if x_result == None:
					self.late_load_apis.append(i.strip(" ").strip("\n").strip(" "))
				else:
						
						for function_name in x_result.splitlines():
								api_name = function_name.split("!")[1].split(" ")[0]
								addr_of_api = function_name.split(" ")[0]
								try:
									mem_rights = pykd.dbgCommand("!address " + addr_of_api)
									if  api_name[:-1] not in self.hooked_apis or function_name.split("!")[1].startswith("Nt",0,2) or "msvcr" in function_name.lower() or "KERNELBASE" in function_name or exe_name in function_name or "execute" not in mem_rights.lower(): #or function_name[9:-21] in iat
										pass
									else:
										self.breakpoints_info.update({addr_of_api:api_name}) # +=function_name[:8]+" "+ api_name  +"\n"
										self.bp_init.append(pykd.setBp(int(function_name[:8] ,16),self.break_hit))	
								except Exception as e:
									print "exception in create_bps()" +str(e)
			except Exception as e:
				print "Exception in hooking:",traceback.print_exc()
					
		pykd.go()
		
	def install_late_loaded_apis_hooks(self):
		still_not_loaded=''
		for i in self.late_load_apis:
			command=''
			b=''
			command="x *!"+ i + '*'
			print type(command), command
			res = pykd.dbgCommand(command)
			if res != None:
				x_result= res.splitlines()
				if len(x_result)==0:
					still_not_loaded+=i.strip(" ").strip("\n").strip(" ")+"\n"
					self.late_load_apis.remove(i)
				else:
						
						for y in x_result:
								try:
									if "KERNELBASE" not in y: # KERNELBASE and kernel32 overlap APIs mostly so skip KERNELBASE
										self.breakpoints_info+=y[:8]+" "+ y[9:-21]  +"\n"
										self.bp_init.append(pykd.setBp(int(y[:8] ,16),self.break_hit))
								except Exception as e:
									print "exception in install_late_loaded_apis_hooks" + str(e)
									
	def check_sections_mem_rights(self):
		exe_handle=pykd.dbgCommand("lm").split("\n")[1].split(" ")[0]
		dh_info=pykd.dbgCommand("!dh "+exe_handle)
		sec_data=''
		start=dh_info.find("SECTION HEADER #")
		sec=''
		sec_data=dh_info[start:len(dh_info)]
		
		for i in sec_data.split("\n"):
			sec+=i+"\n"
			if len(i)==0:
				
				if "Execute Read Write" in sec or "Execute Write" in sec or "Execute Write Copy" in sec:
					addr=hex(int(exe_handle,16)+int(sec.split("\n")[3].strip("    ").split(" ")[0],16))[2:]
					if pykd.dbgCommand("u "+ addr).split(" ")[1]=="0000":
						self.allocated_pointers.update({addr:int(sec.split("\n")[2].strip("    ").split(" ")[0],16)})
					else:
						pass
					sec=''
				elif "Execute Read" in sec:
					sec=''
				else:
					sec=''
	
	# Some static anti-debugging / anti-reversing checks are evaded before starting the execution here
	def antiDebug(self,exe_name,start_address,end_address):
		teb=pykd.dbgCommand("r $teb").split("=")[1].strip("\n")
		# peb!isdebugged
		#TODO: Fix the below command
		#pykd.dbgCommand("eb "+  hex(int(teb,16)+int("1000",16)+2)[2:]+" 0")
		
		#PEB.ProcessHeap.Flags
		a=pykd.dbgCommand("dd "+  hex(int(teb,16)+int("1000",16)+24)[2:]).split("\n")[0].split(" ")[2]
		exe_entry_address=pykd.dbgCommand("r $exentry").split("=")[1].strip("\n")
		self.breakpoints_info+=exe_entry_address+" "+ "exe_entry_address"  +"\n"
		self.bp_init.append(pykd.setBp(int(exe_entry_address ,16),self.break_hit))
		pykd.dbgCommand("ed "+  hex(int(a,16)+64) +" 0")
		pykd.dbgCommand("ed "+  hex(int(a,16)+68) +" 0")
		#peb!heapflags
		isdebugged=pykd.dbgCommand("db "+ hex(int(teb,16)+int("1000",16)+int("68",16))[2:])
		pykd.dbgCommand("eb "+  hex(int(teb,16)+int("1000",16)+int("68",16))[2:]+" 0")
		isdebugged=pykd.dbgCommand("db "+ hex(int(teb,16)+int("1000",16)+int("68",16))[2:])
		
		# Stack segment modification bypass 
		a=pykd.dbgCommand("s "+start_address+ " L"+hex(int(end_address,16)-int(start_address,16))+ " 66 9c 58")
		try:
			for i in a.split("\n"):
				print i.split("  ")[0]
				a=pykd.dbgCommand("!address "+ i.split("  ")[0])
				if "EXECUTE" in a and len(i.split("  ")[0]) > 6:
					b=pykd.dbgCommand("u "+i.split("  ")[0])
					if "???" in b:
						pass
					else:
						# replaces 66 9c 58 # pushf pop eax to cc 33 c0 #  int 3 xor eax,eax
						pykd.dbgCommand("bp "+i.split("  ")[0] + '"' +" eb @eip cc 33 c0;gc;"+ '"')
			
		except:
			pass
			
		try:
			registry_key =_winreg.CreateKeyEx(_winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" +"\\" + exe_name ,0,_winreg.KEY_ALL_ACCESS)
			_winreg.SetValueEx(registry_key, "GlobalFlags", 0, _winreg.REG_SZ, "")
			_winreg.CloseKey(registry_key)
		except Exception as e:
			print "exception in reg" +str(e)
		
	# packer match function , did not output its result to Json output, so it if you need it 
	def match_packer_signature(self,filename):
		filename=filename.strip("'")
		matches=''
		try:
			signatures = peutils.SignatureDatabase(self.signatures_db_file)
			pe = pefile.PE(filename)
			matches = signatures.match_all(pe, ep_only = True)
			try:
				if len(matches)> 0:
					print matches
			except:
				pass
		except Exception as e:
			print "exception in match_packer_signature:"+str(e)
			
	
	def main(self,filename):
		self.check_sections_mem_rights()
		try:
			# Will put breakpoints given in the apis_list.txt and start debugger
			self.create_bps()
		except Exception as e:
			print "Fatal error:", e
			
	def create_results_dir(self):
		try:
			if not os.path.isdir(self.results_path):
				os.makedirs(self.results_path)
			os.makedirs(self.results_path + self.md5)
		except:
			pass
	
	def get_params_of_hooked_apis(self):
		
		path = self.working_dir_path  + "API\\Windows"
		dirs = os.listdir( path )
		for file in dirs:
			file_name = os.path.join(path,file)
			try:
				tree = ET.parse(file_name)
				root = tree.getroot()
				for api in root.iter('Api'):
					if api.attrib['Name'] in self.hooked_apis:
						self.apis_dict.update({api.attrib['Name']:{}})
						d = {}
						param_no = 1
						for child in api:
							if child.tag == "Param":
								d.update({param_no : {"name": child.attrib["Name"],"type": child.attrib["Type"]}})
								param_no +=1 
						self.apis_dict[api.attrib['Name']]["parameters"] = d
			except:	
				pass

		
if __name__=="__main__":
	filename = ''
	self=analysis()
	if len(sys.argv) > 1:
		filename = sys.argv[1]
	else:
		filename = pykd.dbgCommand("lmf").split("\n")[1].split(" ")[6]
	self.md5 = hashlib.md5(open(filename,"rb").read()).hexdigest()
	self.paths.update({"results_dir_path":self.working_dir_path+ "results\\" + self.md5})
	if os.path.exists(self.to_hook_apis_path):
		with open(self.to_hook_apis_path) as f:
			for api in f.readlines():
				self.hooked_apis.append(api.replace("\n",""))
			self.get_params_of_hooked_apis()
	else:
		print "missing hooks file"
		sys.exit(1)
	self.create_results_dir()
	self.match_packer_signature(filename.split(" ")[0])
	self.main(filename)
