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


class platformVulnCheckDocker():
	def __init__(self, reportPath, project, target, reponame, imagename, imagetags, owner):
		self.reportPath = reportPath
		self.sourcefolder = target
		self.target = target
		self.project = project
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


		if target != "local":
			self.username = configData[target]['uid']
			self.password = configData[target]['secret']
			self.repoUrl = configData[target]['url']
			if not self.username and not self.password:
				print "[ INFO ] %s Credential not configured in server.config file" % target
				sys.exit(1)

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
                self.results['header']['repository'] = ''

                self.report_path = reportPath
                now = datetime.now()
                self.report_name = now.strftime("%d-%m-%Y_%H:%M:%S")

                self.results['header']['date'] = self.report_name
                self.results['header']['source type'] = target

                self.vuln_depe = []
                self.vuln_found = []
                self.testedWith = []
                self.dependanciesCount = []
		self.vuln_product = []
		self.med = []
		self.low = []
		self.hig = []
		self.cri = []


	def lt(self, vulnVer, installedVer):
		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "eq" "%s"); then echo "true"; fi' % (vulnVer, installedVer))
		#print 'if $(dpkg --compare-versions "%s" "eq" "%s"); then echo true; fi' % (vulnVer, installedVer)
		if "true" in output:
        		return False

		status, output = commands.getstatusoutput('if $(dpkg --compare-versions "%s" "lt" "%s"); then echo "true"; fi' % (vulnVer, installedVer))
		#print 'if $(dpkg --compare-versions "%s" "gt" "%s"); then echo true; fi' % (vulnVer, installedVer)
    		if "true" in output:
        		return False

		return True
		

	def matchVer(self, cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersions, os_name, severity, image):
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

			if os_name == "ubuntu":
				res['usn_id'] = usn_id
			elif os_name == "debian":
				res['dsa_id'] = usn_id
			else:
				res['id'] = usn_id

			res['reference'] = reference
			res['Installed Version'] = mVersions
			res['Patch Version'] = versions

		   	if product not in self.vuln_product:
				self.vuln_product.append(product)

			if severity not in self.results['Issues'][image]['Issues']:
				self.results['Issues'][image]['Issues'][severity] = []

			if res not in self.results['Issues'][image]['Issues'][severity]:
				self.results['Issues'][image]['Issues'][severity].append(res)

				self.vuln_found.append(cve_id)

				if severity == "medium":
					self.med.append("Medium")
		        	if severity == "high":
					self.hig.append("High")
		        	if severity == "low":
					self.low.append("Low")
		        	if severity == "critical":
					self.cri.append("Critical")

			



	def getVulnData(self, product, mVersion, platform, os_name, image):
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
					self.matchVer(cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, usn_id, reference, mVersion, os_name, severity, image)

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
					self.matchVer(cve_id, product, versions, vectorString, baseScore, pub_date, cwe, name, dsa_id, reference, mVersion, os_name, severity, image)

	def getAZImageJson(self, authUser, authPass, target):
		if target == "azure":
			cmd = 'az acr repository list --username %s --password %s --name %s --out json > /tmp/azure' % (authUser, authPass, self.repoUrl)
			status, output = commands.getstatusoutput(cmd)

			cmd = "cat /tmp/azure"
			status, output = commands.getstatusoutput(cmd)
			output = json.loads(output)

			resArray = []
			for repo in output:
				res = {}
				namespace = repo.split("/")[0]
				image = repo.split("/")[1]
				imgUrl = repo
				res['namespace'] = namespace
				res['image'] = image
				res['imgUrl'] = imgUrl
				resArray.append(res)
				
			return resArray

	def getAWSImageJson(Self, authUser, authPass, target):
		if target == "aws":
			cmd = 'aws ecr describe-repositories'
			status, output = commands.getstatusoutput(cmd)

			output = json.loads(output)
			resArray = []
			for repo in output['repositories']:
				res = {}
				repoName = repo['repositoryName']
				cmd = 'aws ecr describe-images --repository-name %s' % repoName
				status, output = commands.getstatusoutput(cmd)
				output = json.loads(output)
				res['namespace'] = repoName
				res['tags'] = []
				for imgDetail in output['imageDetails']:
				    if 'imageTags' in imgDetail:
					for tag in imgDetail['imageTags']:
						tagName = tag
						res['tags'].append(tagName)
				resArray.append(res)
				
			return resArray

	def getDockerImageJson(Self, authUser, authPass, target):
		if target == "docker":
                    headers = {
                        'Content-Type': 'application/json',
                    }

                    data = '{"username": "%s", "password": "%s"}' % (authUser, authPass)

                    response = requests.post('https://hub.docker.com/v2/users/login/', headers=headers, data=data)

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
				res['namespace'] = namespace
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

		for image in images:
			imageName = re.findall(r'<Image: \'(.*)\'>', str(image))[0]

                        cmd = 'docker run --rm -i -t %s /bin/sh -c "cat /etc/os-release;"' % (imageName)
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
                                        results[imageName]['pkgDetails'].append(res)

		return results

	def getAZImagePkg(self, authUser, authPass, target):
                results = {}
                self.packageLists = {}
                p = 0
                client = docker.from_env()

                cmd = 'sudo az acr login --username %s --password %s --name %s' % (authUser, authPass, self.repoUrl)
                status, output = commands.getstatusoutput(cmd)
                if not re.findall(r'Login Succeeded', str(output)):
                        print "[ OK ] Check Azure credential, something wrong!"
                        sys.exit(1)

                imageJson = self.getAZImageJson(authUser, authPass, target)
                for imgArray in imageJson:
                        	namespace = imgArray['namespace']
                                tagName = imgArray['image']
                                imageName = "%s/%s/%s" % (self.repoUrl, namespace, tagName)
                                image = client.images.pull("%s" % (imageName))

                                cmd = 'docker run --rm -i -t %s /bin/bash -c "cat /etc/os-release"' % (imageName)
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


                                imageName = str(imageName)
                                results[imageName] = {}
                                results[imageName]['os_name'] = str(os_name.strip())
                                results[imageName]['os_version'] = str(os_version.replace('"', '').strip())
                                results[imageName]['os_type'] = str(os_type.strip())

                                if os_name not in self.packageLists:
                                        os_name = os_name.strip()
                                        self.packageLists[os_name] = {}
                                        self.packageLists[os_name]['os_type'] = str(os_type.strip())
                                        self.packageLists[os_name]['os_version'] = str(os_version.replace('"', '').strip())


                                results[imageName]['pkgDetails'] = []

                                if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
                                    cmd = 'docker run --rm -i -t %s /bin/sh -c "dpkg -la > t; cat t"' % (imageName)
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
                                                results[imageName]['pkgDetails'].append(res)

                                cmd = "docker image rm -f %s" % imageName
                                status, output = commands.getstatusoutput(cmd)


                return results


	def getAWSImagePkg(self, authUser, authPass, target):
                results = {}
		self.packageLists = {}
                p = 0
		client = docker.from_env()

		cmd = 'sudo /usr/local/bin/aws ecr get-login-password --region us-east-1 | sudo docker login --username AWS --password-stdin %s' % self.repoUrl
		status, output = commands.getstatusoutput(cmd)
		if not re.findall(r'Login Succeeded', str(output)):
			print "[ OK ] Check AWS credential, something wrong!"
			sys.exit(1)

                imageJson = self.getAWSImageJson(authUser, authPass, target)
                for imgArray in imageJson:
			namespace = imgArray['namespace']
                        for tag in imgArray['tags']:
				tagName = tag
				imageName = "%s/%s:%s" % (self.repoUrl, namespace, tagName)
                                image = client.images.pull("%s" % (imageName))

                                cmd = 'docker run --rm -i -t %s /bin/bash -c "cat /etc/os-release"' % (imageName)
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


                                imageName = str(imageName)
                                results[imageName] = {}
                                results[imageName]['os_name'] = str(os_name.strip())
                                results[imageName]['os_version'] = str(os_version.replace('"', '').strip())
                                results[imageName]['os_type'] = str(os_type.strip())

				if os_name not in self.packageLists:
					os_name = os_name.strip()
                                	self.packageLists[os_name] = {}
                                	self.packageLists[os_name]['os_type'] = str(os_type.strip())
					self.packageLists[os_name]['os_version'] = str(os_version.replace('"', '').strip())


                                results[imageName]['pkgDetails'] = []

				if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
				    cmd = 'docker run --rm -i -t %s /bin/sh -c "dpkg -la > t; cat t"' % (imageName)
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
                                                results[imageName]['pkgDetails'].append(res)

				cmd = "docker image rm -f %s" % imageName
				status, output = commands.getstatusoutput(cmd)


		return results


	def getDockerImagePkg(self, authUser, authPass, target):
                results = {}
		self.packageLists = {}
                p = 0
                client = docker.from_env()
                if authUser:
                        client.login(username=authUser, password=authPass)

                imageJson = self.getDockerImageJson(authUser, authPass, target)

                for imgArray in imageJson:
			namespace = imgArray['namespace']
                        imgName = imgArray['image']
                        for tag in imgArray['tags']:
                                imageName = "%s/%s:%s" % (namespace, imgName, tag)
                                image = client.images.pull("%s" % (imageName))

                                cmd = 'docker run --rm -i -t %s /bin/bash -c "cat /etc/os-release"' % (imageName)
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


                                imageName = str(imageName)
                                results[imageName] = {}
                                results[imageName]['os_name'] = str(os_name.strip())
                                results[imageName]['os_version'] = str(os_version.replace('"', '').strip())
                                results[imageName]['os_type'] = str(os_type.strip())

				if os_name not in self.packageLists:
					os_name = os_name.strip()
                                	self.packageLists[os_name] = {}
                                	self.packageLists[os_name]['os_type'] = str(os_type.strip())
					self.packageLists[os_name]['os_version'] = str(os_version.replace('"', '').strip())


                                results[imageName]['pkgDetails'] = []

				if os_name.strip() == "debian" or os_name.strip() == "ubuntu":
				    cmd = 'docker run --rm -i -t %s /bin/sh -c "dpkg -la > t; cat t"' % (imageName)
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
                                                results[imageName]['pkgDetails'].append(res)

				cmd = "docker image rm -f %s" % imageName
				status, output = commands.getstatusoutput(cmd)

		return results

	def getInstallPkgList(self):
		installPackageLists = {}
		installPackageLists['results'] = []
		self.packageLists = []

		if self.target.lower() == "local":
			installPackageLists = self.getImagePkg()
		
		if self.target.lower() == "docker":
			installPackageLists = self.getDockerImagePkg(self.username, self.password, self.target)

		if self.target.lower() == "aws":
			installPackageLists = self.getAWSImagePkg(self.username, self.password, self.target)

		if self.target.lower() == "azure":
			installPackageLists = self.getAZImagePkg(self.username, self.password, self.target)

			
		return installPackageLists

		
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

		for image in output:
		    if len(output[image]['pkgDetails']) > 0:
			print image

			os_name = output[image]['os_name']
			os_version = output[image]['os_version']
			os_type = output[image]['os_type']

			if image not in self.results['Issues']:
				self.results['Issues'][image] = {}
				self.results['Issues'][image]['os name'] = os_name
				self.results['Issues'][image]['os version'] = os_version
				self.results['Issues'][image]['os type'] = os_type
				self.results['Issues'][image]['Issues'] = {}
			

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
				
			    	self.getVulnData(product, version, platform, os_name, image)

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
		self.responseData = response.json()

	def query_yes_no(self, question, default="yes"):
                valid = {"yes": True, "y": True, "ye": True,
                        "no": False, "n": False}
                if default is None:
                        prompt = " [y/n] "
                elif default == "yes":
                        prompt = " [Y/n] "
                elif default == "no":
                        prompt = " [y/N] "
                else:
                        raise ValueError("invalid default answer: '%s'" % default)

                while True:
                        sys.stdout.write(question + prompt)
                        choice = raw_input().lower()
                        if default is not None and choice == '':
                                return valid[default]
                        elif choice in valid:
                                return valid[choice]
                        else:
                                sys.stdout.write("Please respond with 'yes' or 'no' "
                                        "(or 'y' or 'n').\n")	

		

if __name__ == "__main__":
	parser = argparse.ArgumentParser()

	parser.add_argument('-r', '--reportPath', type=str,  help='Enter Report Path', required=True)
	parser.add_argument('-n', '--projectname', type=str,  help='Enter Project Name', required=True)
	parser.add_argument('-t', '--target', type=str,  help='Enter target type local/docker/aws', required=True, default='local')
	parser.add_argument('-repo', '--reponame', type=str,  help='Enter repository name', default='*')
	parser.add_argument('-image', '--imagename', type=str,  help='Enter Image name', default='*')
	parser.add_argument('-tags', '--imagetags', type=str,  help='Enter Image tags', default='*')
	parser.add_argument('-o', '--owner', type=str,  help='Enter project owner')
	

	parser.add_argument('-v', '--version', action='version',
                    version='%(prog)s 1.0')

	results = parser.parse_args()

	if not results.owner:
		owner = "Unknow"
	else:
		owner = results.owner

	data = """
                     GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the m

Do you want to accept ?
        """

	if res.query_yes_no(data):
		res = platformVulnCheckDocker(results.reportPath, results.projectname, results.target, results.reponame, results.imagename, results.imagetags, owner)
		res.scanPlatformPackage()
	else:
		sys.exit(1)



