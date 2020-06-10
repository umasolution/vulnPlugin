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


class platformVulnCheck():
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
		self.cri = []


	def getsshPackagePlatform(self, cmd):
		s = pxssh.pxssh()
		s.login(self.remoteIp, self.username, self.password)
		s.sendline(cmd)
		s.prompt()
		data = s.before
		s.logout()
		return data	


	def lt(self, vulnVer, installedVer):
		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "eq" "%s"); then echo true; fi' % (vulnVer, installedVer))
		#print 'if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer)
    		if output == "true":
        		return False

		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer))
		#print 'if $(dpkg --compare-versions "%s" "lt" "%s"); then echo true; fi' % (vulnVer, installedVer)
    		if output == "true":
        		return False

		return True
		

	def matchVer(self, cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersions, severity, os_name):
            	if self.lt(versions, mVersions):
                        res = {}
                        res['cve_id'] = cve_id
                        res['product'] = product
                        res['versions'] = versions
                        res['vectorString'] = vectorString
                        res['baseScore'] = baseScore
                        res['pub_date'] = pub_date
                        res['cwe'] = cwe
                        res['name'] = name
			res['severity'] = severity
			severity = severity.lower()

			if severity not in self.results['Issues']:
				self.results['Issues'][severity] = []

                        if os_name == "ubuntu":
                                res['usn_id'] = usn_id

                        if os_name == "debian":
                                res['dsa_id'] = usn_id

                        res['reference'] = reference
                        res['Installed Version'] = mVersions
                        res['Patch Version'] = versions

                        if product not in self.vuln_product:
                                self.vuln_product.append(product)

			if res not in self.results['Issues'][severity]:
                        	self.results['Issues'][severity].append(res)

                                self.vuln_found.append(cve_id)

                                if severity.lower() == "medium":
                                        self.med.append("Medium")
                                if severity.lower() == "high":
                                        self.hig.append("High")
                                if severity.lower() == "low":
                                        self.low.append("Low")
                                if severity.lower() == "critical":
                                        self.cri.append("Critical")



	def getVulnData(self, product, mVersion, platform, os_name):
		if ":" in product:
                        product = product.split(":")[0]

                platformArray = []
                if re.findall(r'Ubuntu\s+(\d+.\d+.\d+)\s+LTS', str(platform)):
                        platform = "%s LTS" % re.findall(r'(Ubuntu\s+\d+.\d+)', str(platform))[0]
                        platformArray.append(platform)
                        platform = "%s ESM" % re.findall(r'(Ubuntu\s+\d+.\d+)', str(platform))[0]
                        platformArray.append(platform)
                elif re.findall(r'Ubuntu\s+(\d+.\d+.\d+)\s+ESM', str(platform)):
                        platform = "%s ESM" % re.findall(r'(Ubuntu\s+\d+.\d+)', str(platform))[0]
                        platformArray.append(platform)
                else:
                        platform = platform
                        platformArray.append(platform)

		for platform in platformArray:
		    if platform in self.responseData:
                        if product in self.responseData[platform]:
                            if os_name == "ubuntu":
                                for row in self.responseData[platform][product]:
                                	cve_id = row['cve_id']
                                	versions = row['version']
                                	vectorString = row['vectorString']
                                	baseScore = row['baseScore']
                                	pub_date = row['pub_date']
                                	cwe = row['cwe_text']
                                	name = row['name']
                                	usn_id = row['usn_id']
					severity = row['severity']
                                	reference = "https://usn.ubuntu.com/%s/" % usn_id
                                	self.matchVer(cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersion, severity, os_name)

			    if os_name == "debian":
                            	for row in self.responseData[platform][product]:
                                	cve_id = row['cve_id']
                                	versions = row['version']
                                	vectorString = row['vectorString']
                                	baseScore = row['baseScore']
                                	pub_date = row['pub_date']
                                	cwe = row['cwe_text']
                                	name = row['name']
                                	dsa_id = row['dsa_id']
					severity = row['severity']
                                	reference = "https://www.debian.org/security/%s/%s" % (cve_id.split("-")[1], dsa_id)
                                	self.matchVer(cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, dsa_id, reference, mVersion, severity, os_name)



	def getInstallPkgList(self):
		self.packageLists = []
		results = {}

		if self.target.lower() == "local":
			cmd = 'cat /etc/os-release'
                        status, output = commands.getstatusoutput(cmd)
                        data = output

			os_name = re.findall(r'^ID=(.*)', str(data), flags=re.MULTILINE)[0]
                        os_version = re.findall(r'^VERSION_ID=(.*)', str(data), flags=re.MULTILINE)[0]
                        if os_name.strip() == "debian":
                                os_type = re.findall(r'^VERSION=\"\d+\s+\((.*)\)\"', str(data), flags=re.MULTILINE)[0]
                        elif  os_name.strip() == "ubuntu":
                                os_type = re.findall(r'PRETTY_NAME=\"(.*)\"', str(data), flags=re.MULTILINE)[0]
                        else:
                                os_type = ''

                        results['os_name'] = str(os_name.strip())
                        results['os_version'] = str(os_version.replace('"', '').strip())
                        results['os_type'] = str(os_type.strip())

                        results['pkgDetails'] = []

			if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
                                cmd = 'dpkg -la > t; cat t'
                                status, output = commands.getstatusoutput(cmd)
                                data = output

                                if re.findall(r'ii\s+(.*?)\s+(.*?)\s+(.*?)\s+', str(data)):
                                    pkgDetails = re.findall(r'ii\s+(.*?)\s+(.*?)\s+(.*?)\s+', str(data))
                                    for pkg in pkgDetails:
                                        res = {}
                                        package = pkg[0]
                                        res['package'] = str(package)
                                        version = pkg[1]
                                        res['version'] = str(version)
                                        archPkg = pkg[2]
                                        res['archPkg'] = str(archPkg)
                                        results['pkgDetails'].append(res)


		
		if self.target.lower() == "remote":
			cmd = "cat /etc/os-release"
			output = self.getsshPackagePlatform(cmd)

			os_name = re.findall(r'^ID=(.*)', str(data), flags=re.MULTILINE)[0]
                        os_version = re.findall(r'^VERSION_ID=(.*)', str(data), flags=re.MULTILINE)[0]
                       	if os_name.strip() == "debian":
                       		os_type = re.findall(r'^VERSION=\"\d+\s+\((.*)\)\"', str(data), flags=re.MULTILINE)[0]
                        elif  os_name.strip() == "ubuntu":
                       		os_type = re.findall(r'PRETTY_NAME=\"(.*)\"', str(data), flags=re.MULTILINE)[0]
                        else:
                               	os_type = ''

                        results['os_name'] = str(os_name.strip())
                        results['os_version'] = str(os_version.replace('"', '').strip())
                       	results['os_type'] = str(os_type.strip())
			results['pkgDetails'] = []

			if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
				cmd = "dpkg -la > t; cat t"
				output = self.getsshPackagePlatform(cmd)
				data = output

                                if re.findall(r'ii\s+(.*?)\s+(.*?)\s+(.*?)\s+', str(data)):
                                	pkgDetails = re.findall(r'ii\s+(.*?)\s+(.*?)\s+(.*?)\s+', str(data))
                                        for pkg in pkgDetails:
                                                res = {}
                                                package = pkg[0]
                                                res['package'] = str(package)
                                                version = pkg[1]
                                                res['version'] = str(version)
                                                archPkg = pkg[2]
                                                res['archPkg'] = str(archPkg)
                                                results['pkgDetails'].append(res)			


			
		return results

		
	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list


	def scanPlatformPackage(self):
		print "[ OK ] Preparing..."
		output = self.getInstallPkgList()
		print "[ OK ] Scanning started"

		self.results['Issues'] = {}
		self.results['packages'] = output

		if len(output['pkgDetails']) > 0:
			os_name = output['os_name']
                        os_version = output['os_version']
                        os_type = output['os_type']

                        self.results['Issues']['os name'] = os_name
                        self.results['Issues']['os version'] = os_version
                        self.results['Issues']['os type'] = os_type
                        self.results['Issues']['Issues'] = {}

			print "[ OK ] Database sync started"
			self.syncData(os_name)
			print "[ OK ] Database sync comleted"

			for pkg in output['pkgDetails']:
                                arch = pkg['archPkg']
                                version = pkg['version']
                                product = pkg['package']

                                if os_name == "ubuntu":
                                        platform = os_type
                                elif os_name == "debian":
                                        platform = os_type
                                else:
                                        platform = os_version

                                self.getVulnData(product, version, platform, os_name)


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
		

	def syncData(self, os_name):
		url = "%s://%s:%s/api/scanDetails/%s" % (self.protocol, self.server, self.port, os_name)
		headers = {
  			'Authorization': 'Basic QWRtaW5pc3RyYXRvcjpWZXJzYUAxMjM=',
  			'Content-Type': 'application/json'
		}
		payload = "{\"data\": \""+ os_name + "\"}"

		response = requests.request("POST", url, headers=headers, data = payload)
		self.responseData = response.json()
		

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


	res = platformVulnCheck(results.reportPath, results.projectname, results.target, owner, results.username, results.password, results.targetIp)
	res.scanPlatformPackage()


