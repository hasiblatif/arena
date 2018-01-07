import json
import sys,os
class Results:
	def __init__(self,log_file_name,md5):
		self.log_file_name = log_file_name
		self.md5 = md5
		self.event_no = 0
		self.output_dict = {}
		#self.output_dict.update({self.md5:{}})
	def write_to_file(self,api,values_dict):
		print "writing to file"
		self.event_no += 1
		self.output_dict.update({self.event_no:{self.md5:{api:values_dict}}})
		#self.output_dict[self.event_no]
		with open(self.log_file_name,"wb") as f:
			json.dump(self.output_dict,f,indent=4)
		
		