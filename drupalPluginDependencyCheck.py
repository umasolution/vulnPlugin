# Developed by : Jays Patel (cyberthreatinfo.ca)
# This script is use to find the Drupal Plugin vulnerabilities.

import time
import os
import glob2
from os import path
import random
import semantic_version
import MySQLdb
import ast
import sys
import commands
import re
import requests
import MySQLdb
import mysql.connector
from pkg_resources import parse_version
import json
from pexpect import pxssh
import argparse
import sqlite3
from datetime import datetime


class drupalPluginVulnerabilities():
	def __init__(self, reportPath, project, targetFolder, owner, stype):
		self.reportPath = reportPath
                self.sourcefolder = targetFolder
                self.project = project
		self.scan_type = stype.lower()

                if not path.exists("server.config"):
                        print "[ INFO ] server configuration json file not found in current directory"
                        sys.exit(1)

		if not os.path.isdir('%s/modules' % self.sourcefolder):
			print "[ INFO ] Modules directory not found in target path, please provide proper drupal path"	
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


	def getDrupalWebToken(self):
		headers = {
    			'Connection': 'keep-alive',
    			'Cache-Control': 'max-age=0',
    			'Upgrade-Insecure-Requests': '1',
    			'Origin': 'http://192.168.0.21',
    			'Content-Type': 'application/x-www-form-urlencoded',
    			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
    			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    			'Referer': 'http://192.168.0.21/drupal/user/login',
    			'Accept-Language': 'en-US,en;q=0.9',
		}

		data = {
  			'name': 'admin',
  			'pass': '123456',
  			'form_build_id': 'form-W2kjoTgKWbo__WiKXkDQa27TYM6zR7X7Gc4129JJmc1',
  			'form_id': 'user_login_form',
  			'op': 'Log in'
		}

		response = requests.post('http://192.168.0.21/drupal/user/login', headers=headers, data=data, verify=False)
		resHeader = response.headers
		resToken = resHeader['Set-Cookie'].split(';')[0]
		return resToken

	def getWebModulePage(self):
		resToken = self.getDrupalWebToken()
		print resToken

		resTokenKey = resToken.split('=')[0]
		resTokenVal = resToken.split('=')[1]
		cookies = {}
		cookies[resTokenKey] = resTokenVal

		headers = {
    			'Connection': 'keep-alive',
    			'Cache-Control': 'max-age=0',
    			'Upgrade-Insecure-Requests': '1',
    			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
    			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    			'Referer': 'http://192.168.0.21/drupal/admin/modules',
    			'Accept-Language': 'en-US,en;q=0.9',
		}
		response = requests.get('http://192.168.0.21/drupal/admin/modules', headers=headers, cookies=cookies, verify=False)
		return response.text


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


	def matchVer(self, project, vulnType, severity, pub_date, vuln_name, versions, reference, cve_id, project_name, mVers):

		mVer = mVers
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

		print "%s - %s - %s" % (project, versions, mVers)

                for vers in versions.split(","):
                    if re.findall(r'\[.*:.*\]', str(vers)):
                        vers1 = re.findall(r'\[(.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\]', str(vers))[0]

                        if self.gtEq(vers1, mVer) and self.ltEq(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)

		    elif re.findall(r'\(.*:.*\]', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\]', str(vers))[0]

                        if self.gt(vers1, mVer) and self.ltEq(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)

		    elif re.findall(r'\[.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\[(.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gtEq(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)

		    elif re.findall(r'\(.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gt(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)

		    elif re.findall(r'\(.*:.*\)', str(vers)):
                        vers1 = re.findall(r'\((.*):', str(vers))[0]
                        vers2 = re.findall(r':(.*)\)', str(vers))[0]

                        if self.gt(vers1, mVer) and self.lt(vers2, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)

		    else:
                        vers1 = str(vers)
                        if self.eq(vers1, mVer):
                                res = {}
                                if severity not in self.results['Issues']:
                                        self.results['Issues'][severity] = []

                                res['plugin'] = str(project)
                                res['severity'] = str(severity)
                                res['cve_id'] = str(cve_id)
                                res['vuln_name'] = str(vuln_name)
                                res['reference'] = str(reference)
                                res['pub_date'] = str(pub_date)
                                res['Versions'] = str(mVers)
                                res['Vulnerability Type'] = str(vulnType)
				res['Project Name'] = str(project_name)

                                if res not in self.results['Issues'][severity]:
                                        self.results['Issues'][severity].append(res)

                                        if severity.lower() == "medium" or severity.lower() == "moderate":
                                                self.med.append("Medium")
                                        if severity.lower() == "high":
                                                self.hig.append("High")
                                        if severity.lower() == "low":
                                                self.low.append("Low")
					if severity.lower() == "critical":
						self.critical.append("Critical")

                                        self.vuln_found.append(project)
                                        if project not in self.vuln_depe:
                                                self.vuln_depe.append(project)


	def getVulnData(self, productName, mVers):
		for res in self.responseData['results'][productName]:
		    if 'project' in res:
                        project_name = res['project_name']
			cve_id = res['cve_id']
			reference = res['reference']
			versions = res['versions']
			vuln_name = res['vulnName']
			pub_date = res['publish_date']
			severity = res['severity']
			vulnType = res['vulnType']
			project = res['project']
	

			self.matchVer(project, vulnType, severity, pub_date, vuln_name, versions, reference, cve_id, project_name, mVers)

	def getConfig(self):
            try:
                url = "%s://%s:%s/api/getConfig/drupalPlugin" % (self.protocol, self.server, self.port)
                headers = {
                        'Authorization': 'Basic QWRtaW5pc3RyYXRvcjpWZXJzYUAxMjM=',
                        'Content-Type': 'application/json'
                }

                response = requests.request("GET", url, headers=headers)
                responseData = response.json()
		return responseData
            except:
                print "[ OK ] Database sync error! Check internet connectivity"
                sys.exit(1)


	def getInstallPkgList(self):
		resultsPackage = []
		self.results['packages'] = []

		resJson = self.getConfig()
		print resJson
		print resJson['details']

		if self.scan_type != "web":
		    for rJson in resJson['details']:
		    	if self.scan_type == "source": 
				location = "%s/modules" % self.sourcefolder
		    	else:
		    		location = rJson['location']
		    	file_regex = rJson['file_regex']
		    	content_version_regex = rJson['content_version_regex']
		    	content_product_regex = rJson['content_product_regex']

		    	for filename in glob2.glob('%s/**/%s' % (location, file_regex), recursive=True):
				res = {}
       				product = ''
        			version = ''
        			fData = open(filename, "r").read()
        			if re.findall(r'%s' % content_version_regex, str(fData)):
                			version = re.findall(r'%s' % content_version_regex, str(fData))[0]
        			if re.findall(r'%s' % content_product_regex, str(fData)):
                			product = re.findall(r'%s' % content_product_regex, str(fData))[0]

        			if product and version:
                			print "%s - %s - %s" % (product, version, filename)
					res['product'] = product
					res['version'] = version
					res['filename'] = filename
					self.results['packages'].append(res)
					if product not in resultsPackage:
						resultsPackage.append(product)

		else:
			resText = self.getWebModulePage()
			print resText
			sys.exit(1)



		return resultsPackage

	def maxValue(self, mVersions):
                ver1 = '0.0'
                for ver in mVersions:
                        if parse_version(ver) > parse_version(ver1):
                                ver1 = ver

                return ver1


	def getUnique(self, lists):
		unique_list = [] 
		for x in lists:
			if x not in unique_list:
				unique_list.append(x)
		return unique_list

	def scanPackage(self):
		self.med = []
                self.hig = []
                self.low = []
		self.critical = []
		packageLists = self.getInstallPkgList()
		print packageLists
		print "=============="
		print self.results
		print "[ OK ] Snyc Data...."
		self.syncData(packageLists)
		print "[ OK ] Preparing..."
		print self.results

		self.results['Issues'] = {}

		print "[ OK ] Scan started"
		for result in self.results['packages']:
			product = result['product']
			versions = result['version']

			print "%s - %s" % (product, versions)
			self.getVulnData(product, versions)

		print "[ OK ] Scan completed"
	
		self.results['header']['tested with'] = ','.join(self.testedWith)
                self.results['header']['severity'] = {}
                self.results['header']['dependancies'] = len(self.dependanciesCount)
                self.results['header']['severity']['low'] = len(self.low)
                self.results['header']['severity']['high'] = len(self.hig)
                self.results['header']['severity']['medium'] = len(self.med)
                self.results['header']['severity']['critical'] = len(self.critical)
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

                url = "%s://%s:%s/api/scanDetailsPlugin/drupalPlugin" % (self.protocol, self.server, self.port)
                headers = {
                        'Authorization': 'Basic QWRtaW5pc3RyYXRvcjpWZXJzYUAxMjM=',
                        'Content-Type': 'application/json'
                }
                payload = "{\"data\": \""+ ','.join(productLists) + "\"}"

                response = requests.request("POST", url, headers=headers, data = payload)
                responseData = response.json()
                self.responseData = responseData
		print self.responseData
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
        parser.add_argument('-o', '--owner', type=str,  help='Enter project owner', required=True)
        parser.add_argument('-p', '--stype', type=str,  help='Enter scan type source/container', required=True)

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
        res = drupalPluginVulnerabilities(results.reportPath, results.projectname, results.target, owner, results.stype)

        if res.query_yes_no(data):
                res.scanPackage()
        else:
                sys.exit(1)
