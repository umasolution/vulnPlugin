# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the python PIP packages vulnerabilities from linux machine and python source project.

import os.path
import docker
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
	def __init__(self, reportPath, project, targetFolder, reponame, imagename, imagetags, owner, username, password):
		self.reportPath = reportPath
		self.sourcefolder = targetFolder
		self.target = targetFolder
		self.project = project
		self.username = username
		self.password = password
		self.reponame = reponame
		self.imagename = imagename
		self.imagetags = imagetags

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



	def getVulnData(self, product, mVersion, platform):
		if product in self.responseData[platform]:
                    for row in self.responseData[platform][product]:
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

	def getRepoImageJson(Self, authUser, authPass):
                headers = {
                        'Content-Type': 'application/json',
                }

                data = '{"username": "%s", "password": "%s"}' % (authUser, authPass)

                response = requests.post('https://hub.docker.com/v2/users/login/', headers=headers, data=data)

		print response.text
                resp = json.loads(response.text)
                token = resp['token']

                headers = {'Authorization': 'JWT %s' % token}
                response = requests.get('https://hub.docker.com/v2/repositories/namespaces/', headers=headers)
                namespaces = json.loads(response.text)


                params = (
                        ('page_size', '10000'),
                )

                resArray = []
                for namespace in namespaces["namespaces"]:
                        response = requests.get('https://hub.docker.com/v2/repositories/%s/' % namespace, headers=headers, params=params)
                        imgNames = json.loads(response.text)

                        for img in imgNames['results']:
                                res = {}
                                imgName = img['name']
                                res['image'] = imgName
                                res['tags'] = []
                                response = requests.get('https://hub.docker.com/v2/repositories/%s/%s/tags/' % (namespace, imgName), headers=headers, params=params)
                                tagNames = json.loads(response.text)

                                for tag in tagNames['results']:
                                        tagsName = tag['name']
                                        res['tags'].append(str(tagsName))

                                resArray.append(res)

                return resArray

	def getImagePkg(self):
                results = {}
		self.packageLists = {}
		

                p = 0
                client = docker.from_env()
		images = client.images.list()
		print images

		for image in images:
			imageName = re.findall(r'<Image: \'(.*)\'>', str(image))[0]
			print imageName

                        cmd = 'docker run --rm -i -t %s /bin/sh -c "cat /etc/os-release;"' % (imageName)
			print cmd
                       	status, output = commands.getstatusoutput(cmd)
                        data = output
			print data

                        os_name = re.findall(r'^ID=(.*)', str(data), flags=re.MULTILINE)[0]
                        os_version = re.findall(r'^VERSION_ID=(.*)', str(data), flags=re.MULTILINE)[0]
                        if os_name.strip() == "debian":
                        	os_type = re.findall(r'^VERSION=\"\d+\s+\((.*)\)\"', str(data), flags=re.MULTILINE)[0]
                        elif  os_name.strip() == "ubuntu":
				os_type = re.findall(r'PRETTY_NAME=\"(.*)\"', str(data), flags=re.MULTILINE)[0]
			else:
				os_type = ''

                        imageName = str(imageName)
                        results[imageName] = {}
                        results[imageName]['os_name'] = str(os_name.strip())
                        results[imageName]['os_version'] = str(os_version.replace('"', '').strip())
                        results[imageName]['os_type'] = str(os_type.strip())

			if os_name not in self.packageLists:
				os_name = os_name.strip()
				self.packageLists[os_name] = {}
				self.packageLists[os_name]['os_type'] = os_type.strip()
				self.packageLists[os_name]['os_version'] = str(os_version.replace('"', '').strip())

                        results[imageName]['pkgDetails'] = []

			if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
                        	cmd = 'docker run --rm -i -t %s /bin/sh -c "dpkg -la > t; cat t"' % (imageName)
				print cmd
                       		status, output = commands.getstatusoutput(cmd)
                        	data = output
				print data
			
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
                                        results[imageName]['pkgDetails'].append(res)

		return results

	def getRepoImagePkg(self, authUser, authPass):
                results = {}
		self.packageLists = {}
                p = 0
                client = docker.from_env()
                if authUser:
                        client.login(username=authUser, password=authPass)
                        print client.images

                imageJson = self.getRepoImageJson(authUser, authPass)

                for imgArray in imageJson:
                        imgName = imgArray['image']
                        for tag in imgArray['tags']:
                                imageName = "jaysnpael/%s:%s" % (imgName, tag)
                                image = client.images.pull("%s" % (imageName))

                                cmd = 'docker run --name test%s_bash --rm -i -t %s /bin/bash -c "cat /etc/os-release; dpkg -la"' % (p, imageName)
                                status, output = commands.getstatusoutput(cmd)

                                data = output

                                os_name = re.findall(r'^ID=(.*)', str(data), flags=re.MULTILINE)[0]
                                os_version = re.findall(r'^VERSION_ID=(.*)', str(data), flags=re.MULTILINE)[0]
                                if os_name.strip() == "debian":
                                        os_type = re.findall(r'^VERSION=\"\d+\s+\((.*)\)\"', str(data), flags=re.MULTILINE)[0]
                                else:
                                        os_type = ''


                                imageName = str(imageName)
                                results[imageName] = {}
                                results[imageName]['os_name'] = str(os_name.strip())
                                results[imageName]['os_version'] = str(os_version.replace('"', '').strip())
                                results[imageName]['os_type'] = str(os_type.strip())

				if os_name not in self.packageLists:
					os_name = os_name.strip()
                                	self.packageLists[os_name] = {}
                                	self.packageLists[os_name]['os_type'] = os_type.strip()
					self.packageLists[os_name]['os_version'] = str(os_version.replace('"', '').strip())


                                results[imageName]['pkgDetails'] = []

				if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
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
                                                results[imageName]['pkgDetails'].append(res)

				cmd = "docker image rm -f %s" % imageName
				status, output = commands.getstatusoutput(cmd)
				print output
		return results

	def getInstallPkgList(self):
		installPackageLists = {}
		installPackageLists['results'] = []
		self.packageLists = []

		if self.target.lower() == "local":
			installPackageLists = self.getImagePkg()
		
		if self.target.lower() == "repository":
			installPackageLists = self.getRepoImagePkg(self.username, self.password)

			
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
		print "[ OK ] Scanning started"
		self.results['Issues'] = {}

		for image in output:
		    if len(output[image]['pkgDetails']) > 0:
			print image
			os_name = output[image]['os_name']
			os_version = output[image]['os_version']
			os_type = output[image]['os_type']

			print "[ OK ] Database sync started"
			self.syncData(os_name)
			print "[ OK ] Database sync comleted"

			for pkg in output[image]['pkgDetails']:
				arch = pkg['archPkg']
				version = pkg['version']
				product = pkg['package']

				if os_name == "ubuntu":
					platform = os_type
				elif os_name == "debian":
					platform = os_type
				else:
					platform = os_version
				
			    	self.getVulnData(product, version, platform)

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
		response = requests.request("POST", url, headers=headers, data=payload)
		print response.text
		self.responseData = response.json()

		print self.responseData
		

if __name__ == "__main__":
	parser = argparse.ArgumentParser()

	parser.add_argument('-r', '--reportPath', type=str,  help='Enter Report Path', required=True)
	parser.add_argument('-n', '--projectname', type=str,  help='Enter Project Name', required=True)
	parser.add_argument('-t', '--target', type=str,  help='Enter target type local/repository', required=True, default='local')
	parser.add_argument('-repo', '--reponame', type=str,  help='Enter repository name', default='*')
	parser.add_argument('-image', '--imagename', type=str,  help='Enter Image name', default='*')
	parser.add_argument('-tags', '--imagetags', type=str,  help='Enter Image tags', default='*')
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

	if results.target.lower() == "repository":
		if not results.username or not results.password:
			print "[ INFO ] Enter remote machine credential with -u and -p argument"
			sys.exit(1)


	res = getUbuntuVulnerabilities(results.reportPath, results.projectname, results.target, results.reponame, results.imagename, results.imagetags, owner, results.username, results.password)
	res.scanUbuntuPackage()


