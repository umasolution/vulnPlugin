# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the Maven packages vulnerabilities from linux machine and python source project.

import time
import glob2
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
import argparse
from tqdm import tqdm
from datetime import datetime


class getMavenVulnerabilities():
	def __init__(self, reportPath, project, targetFolder, owner):
		self.reportPath = reportPath
                self.sourcefolder = targetFolder
                self.project = project


                if not path.exists("server.config"):
                        print "[ INFO ] server configuration json file not found in current directory"
                        sys.exit(1)


                with open('server.config') as f:
                        configData = json.load(f)

                self.tokenId = configData['tokenId']
                self.server = configData['server']
                self.port = configData['port']
                self.protocol = configData['protocol']

		try:
                    url = "%s://%s:%s/api/checkToken/%s" % (self.protocol, self.server, self.port, self.tokenId)
                    response = requests.request("GET", url)
                    tokenData = response.text
                    tokenData = json.loads(tokenData)
                    if tokenData['result']:
                        print "[ OK ] Token valid, start scanning...."
                    else:
                        print "[ INFO ] Token invalid or expire, please login on portal and verify the TokenId"
                        sys.exit(1)
		except:
                    print "[ OK ] Server connection error, Please check internet connectivity"
                    sys.exit(1)

		self.results = {}
                self.results['header'] = {}
                now = datetime.now()
                self.report_name = now.strftime("%d-%m-%Y_%H:%M:%S")
                self.report_path = reportPath

                self.results['header']['Date'] = self.report_name
                self.results['header']['Project'] = self.project
                self.results['header']['Owner'] = owner
                self.results['header']['Target'] = "source"
		self.results['header']['docker'] = "False"

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


	def getLatestVersion(self, product, vendor, mVers):
		response = requests.get('https://repo.packagist.org/p/%s/%s.json' % (vendor, product))
		data = response.text
		data = json.loads(data)
		kData = []
		for k,v in data['packages']['%s/%s' % (vendor, product)].items():
			if re.findall(r'^v%s' % mVers, str(k)):
				value = re.findall(r'%s' % mVers, str(k))[0]
				kData.append(k)

		max = "0.0"
		for v in kData:
			if parse_version(v) > parse_version(max):
				max  = v

		return max
		
	def getMatchVersionLists(self, product, vendor, version):
		response = requests.get('https://semver.mwl.be/packages/%s/%s/match?constraint=%s&minimum-stability=stable' % (vendor, product, version))
		data = response.text
		data = json.loads(data)
		return data

        def maxValue(self, mVersions):
                ver1 = '0.0'
                for ver in mVersions:
                        if parse_version(ver) > parse_version(ver1):
                                ver1 = ver

                return ver1


	def matchVer(self, product, vendor, cve_id, reference, versions, vuln_name, vectorString, baseScore, recommendation, patch, pub_date, severity, mVers, groupId, artifactId, cwe_text):
		mVer = mVers
		
                if severity.lower() == "medium" or severity.lower() == "moderate":
                        severity = "Medium"
                elif severity.lower() == "high":
                        severity = "High"
                elif severity.lower() == "low":
                        severity = "Low"
		elif severity.lower() == "critical":
                        severity = "Critical"

		if not patch:
			patch = versions

                for vers in versions.split(","):
                    if re.findall(r'\[.*:.*\]', str(vers)):
                        vers1 = re.findall(r'\[(.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\]', str(vers))[0]

                        if self.gtEq(vers1, mVer) and self.ltEq(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)

                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)

		    elif re.findall(r'\(.*:.*\]', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\]', str(vers))[0]

                        if self.gt(vers1, mVer) and self.ltEq(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)


                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)

		    elif re.findall(r'\[.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\[(.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gtEq(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)

                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)

		    elif re.findall(r'\(.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gt(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)


                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)

		    elif re.findall(r'\(.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gt(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)

                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)

		    else:
                        vers1 = str(vers)
                        if self.eq(vers1, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = {}
					self.results['Issues'][severity]['data'] = []
                                        self.results['Issues'][severity]['header'] = []

                                res1 = {}
                                res1['CVEID'] = str(cve_id)
                                res1['Product'] = str(product)
                                res1['CWE'] = str(cwe_text)
                                res1['Severity'] = str(severity)

                                res['CVEID'] = str(cve_id)
                                res['Product'] = str(product)
                                res['Vendor'] = str(vendor)
                                res['Severity'] = str(severity)
                                res['Vector String'] = str(vectorString)
                                res['Vulnerability Name'] = str(vuln_name)
                                res['Patched Version'] = str(patch)
                                res['Recommendation'] = str(recommendation)
                                res['Reference'] = str(reference)
                                res['Publish Date'] = str(pub_date)
                                res['Installed Version'] = str(mVers)
				res['GroupId'] = str(groupId)
				res['ArtifactId'] = str(artifactId)
				res['CWE'] = str(cwe_text)


                                if res not in self.results['Issues'][severity]['data']:
					self.results['Issues'][severity]['data'].append(res)
                                        self.results['Issues'][severity]['header'].append(res1)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
                                                self.cri.append("Critical")

                                        self.vuln_found.append(product)
                                        if product not in self.vuln_depe:
                                                self.vuln_depe.append(product)


	def getVulnData(self, productName, mVers):
                for res in self.responseData['results'][productName]:
                    if 'product' in res:
                        product = res['product']
                        vendor = res['vendor']
                        cve_id = res['cve_id']
                        reference = res['reference']
                        versions = res['versions']
                        vuln_name = res['vuln_name']
                        vectorString = res['vectorString']
                        baseScore = res['baseScore']
                        recommendation = res['recommendation']
                        patch = res['patch']
                        pub_date = res['pub_date']
                        severity = res['severity']
			groupId = res['groupId']
			artifactId = res['artifactId']
			cwe_text = res['cwe_text']

			if versions == "*":
				versions = "[0.0:999.999.999.999]"

                        self.matchVer(product, vendor, cve_id, reference, versions, vuln_name, vectorString, baseScore, recommendation, patch, pub_date, severity, mVers, groupId, artifactId, cwe_text)



	def getInstallPkgList(self):
		results = []
		self.installedPackages = []

		for file in glob2.glob('%s/**/*.jar' % (self.sourcefolder), recursive=True):
			res = {}
			product = ''	
			version = ''
			file = os.path.abspath(file)
			filename = os.path.basename(file)


			cmd = 'unzip -p %s META-INF/MANIFEST.MF' % (file)
			status, output = commands.getstatusoutput(cmd)
			if re.findall(r'^(.*)-\d', str(filename)):
				product = re.findall(r'^(.*)-\d', str(filename))[0]

			if re.findall(r'((?:(?:\d+)[.]){1,}(?:\d+).*).jar', str(filename)):
				version = re.findall(r'((?:(?:\d+)[.]){1,}(?:\d+).*).jar', str(filename))[0]
			elif re.findall(r'-(\d+).jar', str(filename)):
				version = re.findall(r'-(\d+).jar', str(filename))[0]
			else:
				version = ''
			

			bundle_name = ''
			bundle_version = ''
			bundle_sym_name = ''

			if re.findall(r'Bundle-Name:\s+(.*)', str(output)):
				bundle_name = re.findall(r'Bundle-Name:\s+(.*)', str(output))[0]
				bundle_name = bundle_name.strip()
			if re.findall(r'Bundle-Version:\s+(.*)', str(output)):
				bundle_version = re.findall(r'Bundle-Version:\s+(.*)', str(output))[0]
				bundle_version = bundle_version.strip()
			if re.findall(r'Bundle-SymbolicName:\s+(.*)',  str(output)):
				bundle_sym_name = re.findall(r'Bundle-SymbolicName:\s+(.*)',  str(output))[0]
				bundle_sym_name = bundle_sym_name.strip()

			res['filepath'] = file
			res['filename'] = filename
			res['product'] = product
			res['version'] = version
			res['bundle_name'] = bundle_name
			res['bundle_version'] = bundle_version
			res['bundle_sym_name'] = bundle_sym_name

			if product not in self.installedPackages:
				self.installedPackages.append(product)

			if bundle_name not in self.installedPackages:
				self.installedPackages.append(bundle_name)

			if bundle_sym_name not in self.installedPackages:
				self.installedPackages.append(bundle_sym_name)

			results.append(res)



		return results
		
			

	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list

	def scanMavenPackage(self):
		print "[ OK ] Preparing..., It's take time to completed."
		output = self.getInstallPkgList()
		self.results['files'] = {}
		self.results['files']['packages'] = output
		print "[ OK ] Database sync started"
		self.syncData(self.installedPackages)
		print "[ OK ] Database sync comleted"
		self.med = []
                self.hig = []
                self.low = []
                self.cri = []
		print "[ OK ] Scanning started"

		self.results['Issues'] = {}
		print "There are total %s files are processing" % len(self.results['files'])
		for d in tqdm(output):
			product = d['product']
			version = d['version']
			if product not in self.dependanciesCount:
				self.dependanciesCount.append(product)
			self.getVulnData(product, version)

		print "[ OK ] Scanning Completed"

		self.results['header']['Tested With'] = ','.join(self.testedWith)
                self.results['header']['Severity'] = {}
                self.results['header']['Total Scanned Dependancies'] = len(self.dependanciesCount)
                self.results['header']['Total Unique Vulnerabilities'] = len(self.vuln_found)
                self.results['header']['Total Vulnerable Dependencies'] = len(self.getUnique(self.vuln_depe))
                self.results['header']['Severity']['Low'] = len(self.low)
                self.results['header']['Severity']['High'] = len(self.hig)
                self.results['header']['Severity']['Medium'] = len(self.med)
                self.results['header']['Severity']['Critical'] = len(self.cri)

		with open("%s/%s.json" % (self.report_path, self.report_name), "w") as f:
			json.dump(self.results, f)
		
		print "[ OK ] Vulnerabilities Report ready - %s/%s" % (self.report_path, self.report_name)

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
                url = "%s://%s:%s/api/scanDetails/maven" % (self.protocol, self.server, self.port)
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
        res = getMavenVulnerabilities(results.reportPath, results.projectname, results.target, owner)

        if res.query_yes_no(data):
                res.scanMavenPackage()
        else:
                sys.exit(1)

