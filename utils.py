import pykd 
import json
import traceback
class Utils:
	def  __init__(self):
		pass
		
	def get_parameter_from_prev_stack(self,param,type,prev_stack):
		return self.evaluate_param(param,type,prev_stack)
	
	def get_parameter(self,param,type):
		esp=pykd.dbgCommand("dd esp")
		return self.evaluate_param(param,type,esp)
	def evaluate_param(self,param,type,a):
		#print a
		try:
			if param == 0: # return value on stack or top of stack
				ret=a.split("\n")[0].split(" ")[2]
			if param == 1:
				ret=a.split("\n")[0].split(" ")[3]
			if param == 2:
				ret=a.split("\n")[0].split(" ")[4]
			if param == 3:
				ret=a.split("\n")[0].split(" ")[5].split("\n")[0]
			if param == 4:
				ret=a.split("\n")[1].split(" ")[2]
			if param == 5:
				ret=a.split("\n")[1].split(" ")[3]
			if param == 6:
				ret=a.split("\n")[1].split(" ")[4]
			if param == 7:
				ret=a.split("\n")[1].split(" ")[5].split("\n")[0]
			if param == 8:
				ret=a.split("\n")[2].split(" ")[2]
			if param == 9:
				ret=a.split("\n")[2].split(" ")[3]
			if param == 10:
				ret=a.split("\n")[2].split(" ")[4].split("\n")[0]
			if param == 11:
				ret=a.d.split("\n")[2].split(" ")[5].split("\n")[0]
			if param == 12:
				ret=a.split("\n")[3].split(" ")[2]
			return ret
		except:
			return "0"
	
	
		
	def return_int(self,addr):
		a = pykd.dbgCommand("dd " + addr)
		ret = a.split("\n")[0].split(" ")[4]
		ret = int(ret,16)
		return ret
	# evaluate string from stack address
	def get_param_value(self,addr,_type):
		
		try:
			d = ''
			_type = _type.lower()
			if _type == "lpcstr" or _type == "lptstr"  or _type == "lpctstr" :
				d_list = pykd.loadBytes(addr,256)
				last_digit = 1
				for j in d_list:
					try:
						if j != 0:
							d += chr(j)
						else:
							if last_digit == 0:
								break
						last_digit = j
					except:
						pass
			elif _type == "lpcwstr" or _type.lower() == "wchar":
				d_list = pykd.loadBytes(addr,512)
				for j in d_list:
					try:
						if j != 0:
							d += chr(j)
						else:
							break
					except:
						pass
			else:
				return addr
			return d
		except:
			print traceback.print_exc()
			return "err"
	
	def read_binary(self,addr,size):
		d_list = pykd.loadBytes(addr,size)
		d = ''
		for j in d_list:
			d += chr(j)
				
		return d
	def read_json(self,json_path):
		a=json.loads(open(json_path).read())
		return a