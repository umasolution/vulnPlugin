# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the python NPM packages vulnerabilities from linux machine and python source project.


import glob2
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
import docker



class getNpmVulnerabilities():
	def __init__(self, reportPath, project, target, reponame, imagename, imagetags, owner):
		self.reportPath = reportPath
                self.target = target
                self.project = project
                self.reponame = reponame
                self.imagename = imagename
                self.imagetags = imagetags

		
		if not path.exists("server.config"):
			print "[ INFO ] server configuration json file not found in current directory"
			sys.exit(1)

		if target == "azure":
                    status, output = commands.getstatusoutput('which az')
                    if len(output) == 0:
                        print "[ OK ] az tool is not installed! installation guide : https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest"
                        sys.exit(1)

                if target == "aws":
                    status, output = commands.getstatusoutput('which aws')
                    if len(output) == 0:
                        print "[ OK ] aws tool is not installed! installation guide : https://aws.amazon.com/cli/"
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
		self.results['images'] = {}
                self.results['header'] = {}
                now = datetime.now()
                self.report_name = now.strftime("%d-%m-%Y_%H:%M:%S")
                self.report_path = reportPath

                self.results['header']['Date'] = self.report_name
                self.results['header']['Project'] = self.project
                self.results['header']['Owner'] = owner
                self.results['header']['Target'] = self.target

		self.vuln_depe = []
		self.vuln_found = []
		self.testedWith = []
		self.namespace = []
		self.imageName = []
		self.dependanciesCount = []


	def gtEq(self, vers1, mVers):
    		if parse_version(mVers) >= parse_version(vers1):
        		return True
    		else:
        		return False

	def gt(self, vers1, mVers):
    		if parse_version(mVers) > parse_version(vers1):
        		return True
    		else:
        		return False

	def ltEq(self, vers1, mVers):
    		if parse_version(mVers) <= parse_version(vers1):
        		return True
    		else:
        		return False


	def lt(self, vers1, mVers):
    		if parse_version(mVers) < parse_version(vers1):
        		return True
    		else:
        		return False

	def eq(self, vers1, mVers):
    		if parse_version(mVers) == parse_version(vers1):
        		return True
    		else:
        		return False

		
	def getMatchVersionLists(self, product):
		response = requests.get('https://cors-proxy-ee2bb0df.internal.npmjs.com/%s' % product)
		data = response.text
		data = json.loads(data)
		versionArray = data['versions']

		versions = []
		for ver in versionArray:
			versions.append(ver)

		return versions

	def maxValue(self, mVersions):
		ver1 = '0.0'
		for ver in mVersions:
    			if parse_version(ver) > parse_version(ver1):
				ver1 = ver

		return ver1
				

	def matchVer(self, versions, cve_id, mVers, product, filename, severity, vectorString, baseScore, pub_date, vendor, reference, vuln_name, patch, recommendation, image, dependancy):
		versArray = self.getMatchVersionLists(product)
		status, output = commands.getstatusoutput("semver -r %s %s" % (mVers, ' '.join(versArray)))
		mVersions = output.split('\n')
		mVer =  self.maxValue(mVersions)

		if not severity:
			severity = "Medium"

		if severity.lower() == "medium" or severity.lower() == "moderate":
			severity = "Medium"
		elif severity.lower() == "high":
			severity = "High"
		elif severity.lower() == "low":
			severity = "Low"
		elif severity.lower() == "critical":
			severity = "Critical"


    		for vers in versions.split(","):
       		    if re.findall(r'\[.*:.*\]', str(vers)):
            		vers1 = re.findall(r'\[(.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\]', str(vers))[0]

            		if self.gtEq(vers1, mVer) and self.ltEq(vers2, mVer):
		    		res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(dependancy)
				res['Versions'] = str(mVers)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)
				
				    
        	    elif re.findall(r'\(.*:.*\]', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\]', str(vers))[0]

            		if self.gt(vers1, mVer) and self.ltEq(vers2, mVer):
				res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(','.join(dependancy))
				res['Versions'] = str(mVer)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

       		    elif re.findall(r'\[.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\[(.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gtEq(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(','.join(dependancy))
				res['Versions'] = str(mVer)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)


        	    elif re.findall(r'\(.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gt(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(','.join(dependancy))
				res['Versions'] = str(mVer)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

        	    elif re.findall(r'\(.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gt(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(','.join(dependancy))
				res['Versions'] = str(mVer)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

        	    else:
            		vers1 = str(vers)
            		if self.eq(vers1, mVer):
				res = {}
				if severity not in self.results['images'][image]['Issues']:
					self.results['images'][image]['Issues'][severity] = []

				res['product'] = str(product)
				res['vendor'] = str(vendor)
				res['severity'] = str(severity)
				res['cve_id'] = str(cve_id)
				res['vectorString'] = str(vectorString)
				res['vuln_name'] = str(vuln_name)
				res['patch'] = str(patch)
				res['recommendation'] = str(recommendation)
				res['reference'] = str(reference)
				res['pub_date'] = str(pub_date)
				res['Introduced through'] = str(','.join(dependancy))
				res['Versions'] = str(mVer)

				if res not in self.results['images'][image]['Issues'][severity]:
		    			self.results['images'][image]['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")
			        	if severity.lower() == "critical":
				    		self.cri.append("critical")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)


	def getVulnData(self, product, mVersions, filename, image, dependancy):
		if product in self.responseData["results"]:
		    for productName in self.responseData["results"][product]:
                        cve_id = productName['cve_id']
			product = productName['product']
			versions = productName['versions']
			severity = productName['severity']
			vectorString = productName['vectorString']
			baseScore = productName['baseScore']
			pub_date = productName['pub_date']
			vendor = productName['vendor']
			reference = productName['reference']
			vuln_name = productName['vuln_name']
			patch = productName['vulnerable version']
			recommendation = productName['recommendation']


			self.matchVer(versions, cve_id, mVersions, product, filename, severity, vectorString, baseScore, pub_date, vendor, reference, vuln_name, patch, recommendation, image, dependancy)

	def getRequires2(self, d, pProduct, vVersion, ppProduct, vvVersion, image):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
                if ppProduct not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
			self.packageLists.append(ppProduct)
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct] = {}
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]:
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'] = []

                self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'].append("%s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(vvVersion)))



	def getRequires3(self, d, pProduct, vVersion, ppProduct, vvVersion, pppProduct, vvvVersion, image):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
                if ppProduct not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
			self.packageLists.append(ppProduct)
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct] = {}
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]:
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'] = []

                self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'].append("%s@%s > %s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(vvVersion), str(pppProduct), str(vvvVersion)))


	def getRequires(self, d, pProduct, vVersion, image):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
		
                if ppProduct not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
			self.packageLists.append(ppProduct)
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct] = {}
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]:
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'] = []

                self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'].append("%s@%s" % (str(pProduct), str(vVersion)))


	def getDependencies(self, d, pProduct, vVersion, image):
            for rDetail in d["dependencies"]:
                ppProduct = str(rDetail)
                ppVersion = d["dependencies"][rDetail]["version"]
		ppVersion = str(ppVersion)

                if ppProduct not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
			self.packageLists.append(ppProduct)
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct] = {}
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]:
                        self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'] = []

                self.resultsPkg['images'][image]['files'][self.filename][self.file][ppProduct]['depend'].append("%s@%s" % (str(pProduct), str(vVersion)))


                if "requires" in d["dependencies"][rDetail]:
                        self.getRequires2(d["dependencies"][rDetail], pProduct, vVersion, ppProduct, ppVersion, image)


                if "dependencies" in d["dependencies"][rDetail]:
                        for rrDetail in d["dependencies"][rDetail]["dependencies"]:
                                pppProduct = rrDetail
				pppProduct = str(pppProduct)
                                if "version" in d["dependencies"][rDetail]["dependencies"][rrDetail]:
                                        pppVersion = d["dependencies"][rDetail]["dependencies"][rrDetail]["version"]
					pppVersion = str(pppVersion)

                                        if "requires" in d["dependencies"][rDetail]["dependencies"][rrDetail]:
                                                self.getRequires3(d["dependencies"][rDetail]["dependencies"][rrDetail], pProduct, vVersion, ppProduct, ppVersion, pppProduct, pppVersion, image)
                                else:
					pppVersion = d["dependencies"][rDetail]["dependencies"][rrDetail]
					pppVersion = str(pppVersion)

                                if pppProduct not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
					self.packageLists.append(pppProduct)
                                        self.resultsPkg['images'][image]['files'][self.filename][self.file][pppProduct] = {}
                                        self.resultsPkg['images'][image]['files'][self.filename][self.file][pppProduct]["version"] = pppVersion

                                if "depend" not in self.resultsPkg['images'][image]['files'][self.filename][self.file][pppProduct]:
                                        self.resultsPkg['images'][image]['files'][self.filename][self.file][pppProduct]["depend"] = []

                                self.resultsPkg['images'][image]['files'][self.filename][self.file][pppProduct]['depend'].append("%s@%s > %s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(ppVersion), str(pppProduct), str(pppVersion)))


	def getAWSImage(self, authUser, authPass, target):
                client = docker.from_env()
                cmd = 'sudo /usr/local/bin/aws ecr get-login-password --region us-east-1 | sudo docker login --username AWS --password-stdin %s' % self.repoUrl
                tatus, output = commands.getstatusoutput(cmd)
                if not re.findall(r'Login Succeeded', str(output)):
                        print "[ OK ] Check AWS credential, something wrong!"
                        sys.exit(1)

                cmd = 'aws ecr describe-repositories'
                status, output = commands.getstatusoutput(cmd)
                output = json.loads(output)
                resArray = []
                for repo in output['repositories']:
                        repoName = repo['repositoryName']
			if repoName not in self.namespace:
				self.namespace.append(repoName)
                        cmd = 'aws ecr describe-images --repository-name %s' % repoName
                        status, output = commands.getstatusoutput(cmd)
                        output = json.loads(output)
                        for imgDetail in output['imageDetails']:
                                if 'imageTags' in imgDetail:
                                        for tag in imgDetail['imageTags']:
                                                tagName = tag
                                                imageName = "%s/%s:%s" % (self.repoUrl, repoName, tagName)
						if imageName not in self.imageName:
							self.imageName.append(imageName)
                                                resArray.append(imageName)

                return resArray

	def getAZImage(self, authUser, authPass, target):
                client = docker.from_env()
                cmd = 'sudo az acr login --username %s --password %s --name %s' % (authUser, authPass, self.repoUrl)
                status, output = commands.getstatusoutput(cmd)
                if not re.findall(r'Login Succeeded', str(output)):
                        print "[ OK ] Check Azure credential, something wrong!"
                        sys.exit(1)

                cmd = 'az acr repository list --username %s --password %s --name %s --out json > /tmp/azure' % (authUser, authPass, self.repoUrl)
                status, output = commands.getstatusoutput(cmd)

                cmd = "cat /tmp/azure"
                status, output = commands.getstatusoutput(cmd)
                output = json.loads(output)

                resArray = []
                for repo in output:
                        namespace = repo.split("/")[0]
			if namespace not in self.namespace:
				self.namespace.append(namespace)
                        image = repo.split("/")[1]
                        imgUrl = repo
                        imageName = "%s/%s/%s" % (self.repoUrl, namespace, image)
			if imageName not in self.imageName:
				self.imageName.append(imageName)
                        resArray.append(imageName)

                return resArray

	def getDockerHubImage(self, authUser, authPass, target):
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
			if namespace not in self.namespace:
				self.namespace.append(namespace)
                        response = requests.get('https://hub.docker.com/v2/repositories/%s/' % namespace, headers=headers, params=params)
                        imgNames = json.loads(response.text)
                        for img in imgNames['results']:
                                imgName = img['name']
                                response = requests.get('https://hub.docker.com/v2/repositories/%s/%s/tags/' % (namespace, imgName), headers=headers, params=params)
                                tagNames = json.loads(response.text)

                                for tag in tagNames['results']:
                                        tagsName = tag['name']
                                        imageName = "%s/%s:%s" % (namespace, imgName, tagsName)
					if imageName not in self.imageName:
						self.imageName.append(imageName)
                                        resArray.append(imageName)

                return resArray


	def getLocalImage(self):
                imagesArray = []
                client = docker.from_env()
                images = client.images.list()
		self.namespace.append("local")
                for image in images:
                        imageName = re.findall(r'<Image: (\'.*\')>', str(image))[0]
                        imgs = re.findall(r'\'(.*?)\'', str(imageName))
                        for img in imgs:
				if img not in self.imageName:
					self.imageName.append(img)
                                imagesArray.append(img)

                return imagesArray


	def getimagepkgVer(self, images):
		self.resultsPkg = {}
		self.resultsPkg['images'] = {}

                for image in images:
                        imageName = image
                        if "/" in imageName:
                                container_name = imageName.split("/")[1]
                                container_name = container_name.replace(":", "_")
                        else:
                                container_name = imageName.replace(":", "_")

                        cmd = 'docker run --name %s -it -d %s' % (container_name, imageName)
                        status, output = commands.getstatusoutput(cmd)
                        data = output

                        cmd = 'docker export %s > /tmp/%s.tar' % (container_name, container_name)
                        status, output = commands.getstatusoutput(cmd)
                        data = output

                        cmd = 'docker rm --force %s' % (container_name)
                        status, output = commands.getstatusoutput(cmd)
                        data = output

                        cmd = 'mkdir /tmp/%s' % container_name
                        status, output = commands.getstatusoutput(cmd)
                        data = output

                        cmd = 'sudo tar -xf /tmp/%s.tar -C /tmp/%s/' % (container_name, container_name)
                        status, output = commands.getstatusoutput(cmd)
                        data = output

                        cmd = 'cat /tmp/%s/etc/os-release' % container_name
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
                        self.resultsPkg['images'][imageName] = {}
                        self.resultsPkg['images'][imageName]['os_name'] = str(os_name.strip())
                        self.resultsPkg['images'][imageName]['os_version'] = str(os_version.replace('"', '').strip())
                        self.resultsPkg['images'][imageName]['os_type'] = str(os_type.strip())

			self.getInstallPkgList("/tmp/%s" % container_name, imageName)

                        cmd = "rm -rf /tmp/%s*" % container_name
                        status, output = commands.getstatusoutput(cmd)
                        data = output

		return self.resultsPkg

	def getPackageLockJson(self, data, image):
                for d in data["dependencies"]:
                        product = str(d)
			if "version" in data["dependencies"][d]:
                        	version = data["dependencies"][d]["version"]
				version = str(version)
			else:
				version = data["dependencies"][d]
				version = str(version)

                        if product not in self.resultsPkg['images'][image]['files'][self.filename][self.file]:
				self.packageLists.append(product)
                                self.resultsPkg['images'][image]['files'][self.filename][self.file][product] = {}
                                self.resultsPkg['images'][image]['files'][self.filename][self.file][product]["version"] = str(version)

                        if 'depend' not in self.resultsPkg['images'][image]['files'][self.filename][self.file][product]:
                                self.resultsPkg['images'][image]['files'][self.filename][self.file][product]["depend"] = []

                        if "requires" in data["dependencies"][d]:
                                self.getRequires(data["dependencies"][d], product, version, image)

                        if "dependencies" in data["dependencies"][d]:
                                self.getDependencies(data["dependencies"][d], product, version, image)

	
	def genPkgVer(self):
                if self.target.lower() == "local":
                        imagesArray = self.getLocalImage()
                        output = self.getimagepkgVer(imagesArray)

                if self.target.lower() == "docker":
                        imagesArray = self.getDockerHubImage(self.username, self.password, self.target)
                        output = self.getimagepkgVer(imagesArray)

                if self.target.lower() == "aws":
                        imagesArray = self.getAWSImage(self.username, self.password, self.target)
                        output = self.getimagepkgVer(imagesArray)

                if self.target.lower() == "azure":
                        imagesArray = self.getAZImage(self.username, self.password, self.target)
                        output = self.getimagepkgVer(imagesArray)

		return output


	def getInstallPkgList(self, location, image):
	    for file in glob2.glob('%s/**/package*.json' % (location), recursive=True):
	    	self.packageLists = []
		file = os.path.abspath(file)
		filename = os.path.basename(file)
		if filename not in self.testedWith:
			self.testedWith.append(filename)

		self.filename = filename
		self.file = file

		with open(file) as f:
			data = json.load(f)

		if 'lockfileVersion' in data:
			lock = True
		else:
			lock = False
			

		if 'files' not in self.resultsPkg['images'][image]:
			self.resultsPkg['images'][image]['files'] = {}

		if self.filename not in self.resultsPkg['images'][image]['files']:
			self.resultsPkg['images'][image]['files'][self.filename] = {}

		self.resultsPkg['images'][image]['files'][self.filename][file] = {}


		if lock:
		    	self.resultsPkg['images'][image]['files'][self.filename][file]['lock'] = {}
			self.getPackageLockJson(data, image)

		if not lock:	
		    if 'dependencies' in data:
		    	self.resultsPkg['images'][image]['files'][self.filename][file]['dependencies'] = []
			for d in data['dependencies']:
		    	    if "/" in d:
				res = {}
				product = d.split("/")[1]
				if product not in self.packageLists:
					self.packageLists.append(str(product))
				version = data['dependencies'][d]
				res['product'] = product
				res['version'] = version
				res = ast.literal_eval(json.dumps(res))
				self.resultsPkg['images'][image]['files'][self.filename][file]['dependencies'].append(res)
			    else:
				res = {}
				product = d
				version = data['dependencies'][d]
				res['product'] = product
				if product not in self.packageLists:
					self.packageLists.append(str(product))
				res['version'] = version
				res = ast.literal_eval(json.dumps(res))
				self.resultsPkg['images'][image]['files'][self.filename][file]['dependencies'].append(res)

		    if 'devDependencies' in data:
		    	self.resultsPkg['images'][image]['files'][self.filename][file]['devDependencies'] = []
		    	for d in data['devDependencies']:
			    if "/" in d:
				res = {}
				product = d.split("/")[1]
				if product not in self.packageLists:
					self.packageLists.append(str(product))
				version = data['devDependencies'][d]
				res['product'] = product
				res['version'] = version
				res = ast.literal_eval(json.dumps(res))
				self.resultsPkg['images'][image]['files'][self.filename][file]['devDependencies'].append(res)
			    else:
				res = {}
				product = d
				if product not in self.packageLists:
					self.packageLists.append(str(product))
				version = data['devDependencies'][d]
				res['product'] = product
				res['version'] = version
				res = ast.literal_eval(json.dumps(res))
				self.resultsPkg['images'][image]['files'][self.filename][file]['devDependencies'].append(res)

		
	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list

	def scanNpmPackage(self):
		print "[ OK ] Preparing..."
		output = self.genPkgVer()
		self.med = []
		self.hig = []
		self.low = []
		self.cri = []

		print "[ OK ] Database sync started"
		self.syncData(self.packageLists)
		print "[ OK ] Database sync comleted"

		print "[ OK ] Scanning started"

		for image in output['images']:
		    if image not in self.results['images']:
			self.results['images'][image] = {}
		    	self.results['images'][image]['Issues'] = {}

		    if 'files' in output['images'][image]:
		        for filename in output['images'][image]['files']:
			    if filename not in self.testedWith:
				self.testedWith.append(filename)
		    	    if filename != "header":
		                for file in output['images'][image]['files'][filename]:
		            	    if 'lock' not in output['images'][image]['files'][filename][file]:
					if 'devDependencies' in output['images'][image]['files'][filename][file]:
	   	    	                    for d in output['images'][image]['files'][filename][file]['devDependencies']:
				    	    	product = d['product']
				    	    	version = d['version']
						if product not in self.dependanciesCount:
				    	    		self.dependanciesCount.append(product)
				    	    	self.getVulnData(product, version, filename, image, '')

					if 'dependencies' in output['images'][image]['files'][filename][file]:
		    	                    for d in output['images'][image]['files'][filename][file]['dependencies']:
				    	    	product = d['product']
				    	    	version = d['version']
						if product not in self.dependanciesCount:
				    	    		self.dependanciesCount.append(product)
				    	    	self.getVulnData(product, version, filename, image, '')

		    	            if 'lock' in output['images'][image]['files'][filename][file]:
			                for d in output['images'][image]['files'][filename][file]:
			            	    if d != "lock":
			    	                if "/" in d:
					    	    product = d.split("/")[1]
					    	    version = output['images'][image]['files'][filename][file][d]["version"]
			    	                else:
					    	    product = d
					    	    version = output['images'][image]['files'][filename][file][d]["version"]

						if product not in self.dependanciesCount:
				    	    		self.dependanciesCount.append(product)
			    	                dependancyDetails = output['images'][image]['files'][filename][file][d]['depend']
			    	                self.getVulnData(product, version, filename, image, dependancyDetails)


		print "[ OK ] Scanning Completed"
			
		self.results['header']['Tested With'] = ','.join(self.testedWith)
                self.results['header']['Severity'] = {}
                self.results['header']['Total Scanned Dependancies'] = len(self.dependanciesCount)
                self.results['header']['Total Vulnerabilities'] = len(self.vuln_found)
                self.results['header']['Total Vulnerable Dependencies'] = len(self.getUnique(self.vuln_depe))
		self.results['header']['Total Scanned Namespaces'] = len(self.namespace)
		self.results['header']['Total Scanned Images'] = len(self.imageName)
                self.results['header']['Severity']['Low'] = len(self.low)
                self.results['header']['Severity']['High'] = len(self.hig)
                self.results['header']['Severity']['Medium'] = len(self.med)
                self.results['header']['Severity']['Critical'] = len(self.cri)


		with open("%s/%s.json" % (self.report_path, self.report_name), "w") as f:
			json.dump(self.results, f)
		
		print "[ OK ] Vulnerabilities Report ready - %s/%s.json" % (self.report_path, self.report_name)


		url = "%s://%s:%s/api/report-upload/language/%s" % (self.protocol, self.server, self.port, self.tokenId)
		fin = open('%s/%s.json' % (self.report_path, self.report_name), 'rb')
		files = {'file': fin}
		response = requests.post(url, files = files)

		if response.status_code == 201:
			print "[ OK ] Report Uploaded on server"
		else:
			print "[ ERROR ] Report Upload Error"
		

	def syncData(self, productLists):
	    try:
		url = "%s://%s:%s/api/scanDetails/npm" % (self.protocol, self.server, self.port)
		headers = {
  			'Authorization': 'Basic QWRtaW5pc3RyYXRvcjpWZXJzYUAxMjM=',
  			'Content-Type': 'application/json'
		}
		payload = "{\"data\": \""+ ','.join(productLists) + "\"}"

		response = requests.request("POST", url, headers=headers, data = payload)
		responseData = response.json()
		self.responseData = responseData
	    except:
		print "[ OK ] Database sync error! Check internet connectivity"
		sys.exit(1)


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

	parser = argparse.ArgumentParser()
        parser.add_argument('-r', '--reportPath', type=str,  help='Enter Report Path', required=True)
        parser.add_argument('-n', '--projectname', type=str,  help='Enter Project Name', required=True)
        parser.add_argument('-t', '--target', type=str,  help='Enter target type local/docker/aws/azure', required=True, default='local')
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
	res = getNpmVulnerabilities(results.reportPath, results.projectname, results.target, results.reponame, results.imagename, results.imagetags, owner)

	if res.query_yes_no(data):
		res.scanNpmPackage()
	else:
		sys.exit(1)


