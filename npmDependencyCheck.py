# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the python NPM packages vulnerabilities from linux machine and python source project.


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



class getNpmVulnerabilities():
	def __init__(self, reportPath, project, targetFolder, owner):
		self.reportPath = reportPath
		self.sourcefolder = targetFolder
		self.project = project

		
		if not path.exists("server.config"):
			print "[ INFO ] server configuration json file not found in current directory"
			sys.exit(1)

		if path.exists("%s/package-lock.json" % self.sourcefolder) or path.exists("%s/package.json" % self.sourcefolder):
			pass
		else:
			print "[ INFO ] Package Json file not found, which files are require to scan source"
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
				

	def matchVer(self, versions, cve_id, mVers, product, filename, severity, vectorString, baseScore, pub_date, vendor, reference, vuln_name, patch, recommendation, dependancy):
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

    		for vers in versions.split(","):
       		    if re.findall(r'\[.*:.*\]', str(vers)):
            		vers1 = re.findall(r'\[(.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\]', str(vers))[0]

            		if self.gtEq(vers1, mVer) and self.ltEq(vers2, mVer):
		    		res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)
				
				    
        	    elif re.findall(r'\(.*:.*\]', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\]', str(vers))[0]

            		if self.gt(vers1, mVer) and self.ltEq(vers2, mVer):
				res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

       		    elif re.findall(r'\[.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\[(.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gtEq(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)


        	    elif re.findall(r'\(.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gt(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

        	    elif re.findall(r'\(.*:.*\)', str(vers)):
            		vers1 = re.findall(r'\((.*):', str(vers))[0]
            		vers2 = re.findall(r':(.*)\)', str(vers))[0]

            		if self.gt(vers1, mVer) and self.lt(vers2, mVer):
				res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)

        	    else:
            		vers1 = str(vers)
            		if self.eq(vers1, mVer):
				res = {}
				if severity not in self.results['Issues']:
					self.results['Issues'][severity] = []

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

				if res not in self.results['Issues'][severity]:
		    			self.results['Issues'][severity].append(res)

			        	if severity.lower() == "medium" or severity.lower() == "moderate":
				    		self.med.append("Medium")
			        	if severity.lower() == "high":
				    		self.hig.append("High")
			        	if severity.lower() == "low":
				    		self.low.append("Low")

					self.vuln_found.append(product)
					if product not in self.vuln_depe:
						self.vuln_depe.append(product)


	def getVulnData(self, product, mVersions, filename, dependancy):
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


			self.matchVer(versions, cve_id, mVersions, product, filename, severity, vectorString, baseScore, pub_date, vendor, reference, vuln_name, patch, recommendation, dependancy)

	def getRequires2(self, d, pProduct, vVersion, ppProduct, vvVersion):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
                if ppProduct not in self.results[self.filename]:
			self.packageLists.append(ppProduct)
                        self.results[self.filename][ppProduct] = {}
                        self.results[self.filename][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.results[self.filename][ppProduct]:
                        self.results[self.filename][ppProduct]['depend'] = []

                self.results[self.filename][ppProduct]['depend'].append("%s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(vvVersion)))



	def getRequires3(self, d, pProduct, vVersion, ppProduct, vvVersion, pppProduct, vvvVersion):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
                if ppProduct not in self.results[self.filename]:
			self.packageLists.append(ppProduct)
                        self.results[self.filename][ppProduct] = {}
                        self.results[self.filename][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.results[self.filename][ppProduct]:
                        self.results[self.filename][ppProduct]['depend'] = []

                self.results[self.filename][ppProduct]['depend'].append("%s@%s > %s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(vvVersion), str(pppProduct), str(vvvVersion)))


	def getRequires(self, d, pProduct, vVersion):
            for rDetail in d["requires"]:
                ppProduct = str(rDetail)
                ppVersion = d["requires"][rDetail]
		ppVersion = str(ppVersion)
		
                if ppProduct not in self.results[self.filename]:
			self.packageLists.append(ppProduct)
                        self.results[self.filename][ppProduct] = {}
                        self.results[self.filename][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.results[self.filename][ppProduct]:
                        self.results[self.filename][ppProduct]['depend'] = []

                self.results[self.filename][ppProduct]['depend'].append("%s@%s" % (str(pProduct), str(vVersion)))


	def getDependencies(self, d, pProduct, vVersion):
            for rDetail in d["dependencies"]:
                ppProduct = str(rDetail)
                ppVersion = d["dependencies"][rDetail]["version"]
		ppVersion = str(ppVersion)

                if ppProduct not in self.results[self.filename]:
			self.packageLists.append(ppProduct)
                        self.results[self.filename][ppProduct] = {}
                        self.results[self.filename][ppProduct]["version"] = str(ppVersion)

                if 'depend' not in self.results[self.filename][ppProduct]:
                        self.results[self.filename][ppProduct]['depend'] = []

                self.results[self.filename][ppProduct]['depend'].append("%s@%s" % (str(pProduct), str(vVersion)))


                if "requires" in d["dependencies"][rDetail]:
                        self.getRequires2(d["dependencies"][rDetail], pProduct, vVersion, ppProduct, ppVersion)


                if "dependencies" in d["dependencies"][rDetail]:
                        for rrDetail in d["dependencies"][rDetail]["dependencies"]:
                                pppProduct = rrDetail
				pppProduct = str(pppProduct)
                                if "version" in d["dependencies"][rDetail]["dependencies"][rrDetail]:
                                        pppVersion = d["dependencies"][rDetail]["dependencies"][rrDetail]["version"]
					pppVersion = str(pppVersion)

                                        if "requires" in d["dependencies"][rDetail]["dependencies"][rrDetail]:
                                                self.getRequires3(d["dependencies"][rDetail]["dependencies"][rrDetail], pProduct, vVersion, ppProduct, ppVersion, pppProduct, pppVersion)
                                else:
					pppVersion = d["dependencies"][rDetail]["dependencies"][rrDetail]
					pppVersion = str(pppVersion)

                                if pppProduct not in self.results[self.filename]:
					self.packageLists.append(pppProduct)
                                        self.results[self.filename][pppProduct] = {}
                                        self.results[self.filename][pppProduct]["version"] = pppVersion

                                if "depend" not in self.results[self.filename][pppProduct]:
                                        self.results[self.filename][pppProduct]["depend"] = []

                                self.results[self.filename][pppProduct]['depend'].append("%s@%s > %s@%s > %s@%s" % (str(pProduct), str(vVersion), str(ppProduct), str(ppVersion), str(pppProduct), str(pppVersion)))

	def getPackageLockJson(self, data):
                for d in data["dependencies"]:
                        product = str(d)
			if "version" in data["dependencies"][d]:
                        	version = data["dependencies"][d]["version"]
				version = str(version)
			else:
				version = data["dependencies"][d]
				version = str(version)

                        if product not in self.results[self.filename]:
				self.packageLists.append(product)
                                self.results[self.filename][product] = {}
                                self.results[self.filename][product]["version"] = str(version)

                        if 'depend' not in self.results[self.filename][product]:
                                self.results[self.filename][product]["depend"] = []

                        if "requires" in data["dependencies"][d]:
                                self.getRequires(data["dependencies"][d], product, version)

                        if "dependencies" in data["dependencies"][d]:
                                self.getDependencies(data["dependencies"][d], product, version)


	def getInstallPkgList(self):
		self.packageLists = []
		fileArray = ['package-lock.json', 'package.json']
		for filename in fileArray:
		    if path.exists("%s/%s" % (self.sourcefolder, filename)):  	
			self.testedWith.append(filename)
			file = "%s/%s" % (self.sourcefolder, filename)

			with open(file) as f:
				data = json.load(f)

			if 'lockfileVersion' in data:
				lock = True
			else:
				lock = False
			
			self.filename = filename
			self.results[self.filename] = {}

			if lock:
			    	self.results[self.filename]['lock'] = {}
				self.getPackageLockJson(data)

			if not lock:	
			    if 'dependencies' in data:
			    	self.results[self.filename]['dependencies'] = []
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
					self.results[self.filename]['dependencies'].append(res)
				    else:
					res = {}
					product = d
					version = data['dependencies'][d]
					res['product'] = product
					if product not in self.packageLists:
						self.packageLists.append(str(product))
					res['version'] = version
					res = ast.literal_eval(json.dumps(res))
					self.results[self.filename]['dependencies'].append(res)

			    if 'devDependencies' in data:
			    	self.results[self.filename]['devDependencies'] = []
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
					self.results[self.filename]['devDependencies'].append(res)
				    else:
					res = {}
					product = d
					if product not in self.packageLists:
						self.packageLists.append(str(product))
					version = data['devDependencies'][d]
					res['product'] = product
					res['version'] = version
					res = ast.literal_eval(json.dumps(res))
					self.results[self.filename]['devDependencies'].append(res)


		return self.results
		
	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list

	def scanNpmPackage(self):
		print "[ OK ] Preparing..."
		output = self.getInstallPkgList()
		#self.results['jsonFiles'] = output
		self.med = []
		self.hig = []
		self.low = []

		fileArray = ['package-lock.json', 'package.json']

		print "[ OK ] Database sync started"
		self.syncData(self.packageLists)
		print "[ OK ] Database sync comleted"

		print "[ OK ] Scanning started"

		self.results['Issues'] = {}
		for filename in fileArray:
		    if 'lock' not in output[filename]:
	   	    	for d in output[filename]['devDependencies']:
				product = d['product']
				version = d['version']
				self.dependanciesCount.append(product)
				self.getVulnData(product, version, filename, '')

		    	for d in output[filename]['dependencies']:
				product = d['product']
				version = d['version']
				self.dependanciesCount.append(product)
				self.getVulnData(product, version, filename, '')

		    if 'lock' in output[filename]:
			for d in output[filename]:
			    if d != "lock":
			    	if "/" in d:
					product = d.split("/")[1]
					version = output[filename][d]["version"]
			    	else:
					product = d
					version = output[filename][d]["version"]

				self.dependanciesCount.append(product)
			    	dependancyDetails = output[filename][d]['depend']
			    	self.getVulnData(product, version, filename, dependancyDetails)


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

	parser.add_argument('-r', '--reportPath', type=str,  help='Enter Report Path', required=True)
	parser.add_argument('-n', '--projectname', type=str,  help='Enter Project Name', required=True)
	parser.add_argument('-t', '--target', type=str,  help='Enter target source folder', required=True)
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
	res = getNpmVulnerabilities(results.reportPath, results.projectname, results.target, owner)

	if res.query_yes_no(data):
		res.scanNpmPackage()
	else:
		sys.exit(1)


