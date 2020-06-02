# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the python PIP packages vulnerabilities from linux machine and python source project.

import os.path
import time
import random
import os.path
from os import path
import ast
import sys
import commands
import re
import requests
from pkg_resources import parse_version
import json
from pexpect import pxssh
import argparse
from datetime import datetime


class getUbuntuVulnerabilities():
	def __init__(self, reportPath, project, targetFolder, owner, username, password, remoteIp):
		self.reportPath = reportPath
		self.sourcefolder = targetFolder
		self.target = targetFolder
		self.project = project
		self.username = username
		self.password = password
		self.remoteIp = remoteIp

		if not path.exists("server.config"):
			print "[ INFO ] server configuration json file not found in current directory"
			sys.exit(1)


		with open('server.config') as f:
			configData = json.load(f)

		self.tokenId = configData['tokenId']
		self.server = configData['server']
		self.port = configData['port']
		self.protocol = configData['protocol']

		url = "%s://%s:%s/api/checkToken/%s" % (self.protocol, self.server, self.port, self.tokenId)	
		response = requests.request("GET", url)
		tokenData = response.text
		tokenData = json.loads(tokenData)
		if tokenData['result']:
			print "[ OK ] Token valid, start scanning...."
		else:
			print "[ INFO ] Token invalid or expire, please login on portal and verify the TokenId"
			sys.exit(1)
		
		self.results = {}
                self.results['header'] = {}
                self.results['header']['project'] = self.project
                self.results['header']['project owner'] = owner
                path1=os.path.dirname(self.reportPath)
                self.results['header']['repository'] = os.path.basename(path1)

                self.report_path = reportPath
                now = datetime.now()
                self.report_name = now.strftime("%d-%m-%Y_%H:%M:%S")

                self.results['header']['date'] = self.report_name
                self.results['header']['source type'] = "source"

                self.vuln_depe = []
                self.vuln_found = []
                self.testedWith = []
                self.dependanciesCount = []
		self.vuln_product = []
		self.med = []
		self.low = []
		self.hig = []


	def getsshPackageUbuntu(self):
		s = pxssh.pxssh()
		s.login(self.remoteIp, self.username, self.password)
		s.sendline('sudo apt list --installed')
		s.prompt()
		data = s.before
		s.logout()
		return data	


	def lt(self, vulnVer, installedVer):
		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "eq" "%s"); then echo true; fi' % (vulnVer, installedVer))
		print 'if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer)
    		if output == "true":
        		return False

		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer))
		print 'if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer)
    		if output == "true":
        		return False

		return True
		

	def matchVer(self, cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersions):
		severity = "Medium"
            	if self.lt(versions, mVersions):
			print "1 - %s" % versions
			print "2 - %s" % mVersions
			if product not in self.results['Issues']:
				self.results['Issues'][product] = []

			res = {}
			res['cve_id'] = cve_id
			res['versions'] = versions
			res['vectorString'] = vectorString
			res['baseScore'] = baseScore
			res['pub_date'] = pub_date
			res['cwe'] = cwe
			res['name'] = name
			res['usn_id'] = usn_id
			res['reference'] = reference
			res['Installed Version'] = mVersions
			res['Vulnerable Version'] = versions

			self.results['Issues'][product].append(res)


		   	if product not in self.vuln_product:
				self.vuln_product.append(product)

		   	if cve_id not in self.vuln_found:
				self.vuln_found.append(cve_id)

				if severity == "Medium":
					self.med.append("Medium")
		        	if severity == "high":
					self.hig.append("High")
		        	if severity == "low":
					self.low.append("Low")



	def getVulnData(self, product, mVersion):
		if product in self.responseData[self.platform]:
                    for row in self.responseData[self.platform][product]:
                        cve_id = row['cve_id']
			versions = row['version']
			vectorString = row['vectorString']
			baseScore = row['baseScore']
			pub_date = row['pub_date']
			cwe = row['cwe_text']
			name = row['name']
			usn_id = row['usn_id']
			reference = "https://usn.ubuntu.com/%s/" % usn_id
			print "1 - %s" % cve_id
			self.matchVer(cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersion)


	def getInstallPkgList(self):
		installPackageLists = {}
		installPackageLists['results'] = []
		self.packageLists = []

		if self.target.lower() == "local":
			cmd = "sudo apt list --installed"
			status, output = commands.getstatusoutput(cmd)
		
		if self.target.lower() == "remote":
			output = self.getsshPackageUbuntu()

		for detail in output.split("\n"):
		    if "/" in detail:
			if re.findall(r'^(.*)\/', str(detail)):
				product = re.findall(r'^(.*)\/', str(detail))[0]
			if re.findall(r'now (.*?) ', str(detail)):
				version = re.findall(r'now (.*?) ', str(detail))[0]

			if product and version:
				res = {}
				res['product'] = product
				res['version'] = version
				installPackageLists['results'].append(res)
				self.packageLists.append(product)
			
		return installPackageLists

		
	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list


	def scanUbuntuPackage(self):
		self.platform = "Ubuntu 16.04 LTS"
		print "[ OK ] Preparing..."
		output = self.getInstallPkgList()
	
		print "[ OK ] Database sync started"
		self.syncData(self.packageLists)
		print "[ OK ] Database sync comleted"

		print "[ OK ] Scanning started"

		self.results['Issues'] = {}

		for d in output['results']:
				product = d['product']
				version = d['version']
			    	self.getVulnData(product, version)

		print "[ OK ] Scanning Completed"
			
		self.results['header']['tested with'] = ','.join(self.testedWith)
                self.results['header']['severity'] = {}
                self.results['header']['dependancies'] = len(self.dependanciesCount)
                self.results['header']['severity']['low'] = len(self.low)
                self.results['header']['severity']['high'] = len(self.hig)
                self.results['header']['severity']['medium'] = len(self.med)
                self.results['header']['vulnerabilities found'] = len(self.vuln_found)
                self.results['header']['vulnerable dependencies'] = len(self.getUnique(self.vuln_depe))


		with open("%s/%s.json" % (self.report_path, self.report_name), "w") as f:
			json.dump(self.results, f)
		
		print "[ OK ] Vulnerabilities Report ready - %s/%s.json" % (self.report_path, self.report_name)


		url = "%s://%s:%s/api/report-upload/platform/%s" % (self.protocol, self.server, self.port, self.tokenId)
		fin = open('%s/%s.json' % (self.report_path, self.report_name), 'rb')
		files = {'file': fin}
		response = requests.post(url, files = files)

		if response.status_code == 201:
			print "[ OK ] Report Uploaded on server"
		else:
			print "[ ERROR ] Report Upload Error"
		

	def syncData(self, productLists):
		url = "%s://%s:%s/api/scanDetails/ubuntu" % (self.protocol, self.server, self.port)
		headers = {
  			'Authorization': 'Basic QWRtaW5pc3RyYXRvcjpWZXJzYUAxMjM=',
  			'Content-Type': 'application/json'
		}
		payload = "{\"platform\": \"Ubuntu 16.04 LTS\", \"data\": \""+ ','.join(productLists) + "\"}"

		response = requests.request("POST", url, headers=headers, data = payload)
		self.responseData = response.json()

		print self.responseData
		

if __name__ == "__main__":
	parser = argparse.ArgumentParser()

	parser.add_argument('-r', '--reportPath', type=str,  help='Enter Report Path', required=True)
	parser.add_argument('-n', '--projectname', type=str,  help='Enter Project Name', required=True)
	parser.add_argument('-t', '--target', type=str,  help='Enter target type local/remote', required=True, default='local')
	parser.add_argument('-ip', '--targetIp', type=str,  help='Enter target machine IP address')
	parser.add_argument('-o', '--owner', type=str,  help='Enter project owner')
	parser.add_argument('-u', '--username', type=str,  help='Enter remote machine username')
	parser.add_argument('-p', '--password', type=str,  help='Enter remote machine password')
	

	parser.add_argument('-v', '--version', action='version',
                    version='%(prog)s 1.0')

	results = parser.parse_args()

	if not results.owner:
		owner = "Unknow"
	else:
		owner = results.owner

	if results.target.lower() == "remote":
		if not results.username or not results.password or not results.targetIp:
			print "[ INFO ] Enter remote machine credential with -u and -p argument"
			sys.exit(1)


	res = getUbuntuVulnerabilities(results.reportPath, results.projectname, results.target, owner, results.username, results.password, results.targetIp)
	res.scanUbuntuPackage()


