#!/bin/python3
import requests
import json
import re
import pymisp
import logging
import os
import datetime
import time
today=str(datetime.date.today())

url_nvd = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=aws&isExactMatch=true&modStartDate=2021-01-01T00:00:00:000 UTC-03:00"
#url_nvd = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=elasticsearch&modStartDate="+today+"T00:00:00:000 UTC-03:00"
#url_nvd = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:o:apache&cvssV3Severity=CRITICAL"
#url_nvd = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=dns+server&isExactMatch=true&"
url_post = "http://elastisearch_host:9200/nvd-"+today+"/_doc"
headers_post = {'Content-Type': 'application/json'}
r = requests.get(url_nvd, verify=False)
print(r.status_code)
json_data=json.loads(r.text)
for i in json_data['result']['CVE_Items']:
  cve = i['cve']['CVE_data_meta']['ID']
  assigner = i['cve']['CVE_data_meta']['ASSIGNER']
#  description_data = i['cve']['description']
#  for b in i['configurations']['nodes']:
#    for x in b['cpe_match']:
#      cpe = x['cpe23Uri']
  for a in i['cve']['description']['description_data']:
    description = a['value']
  
  cvssv3_vector_string = i['impact']['baseMetricV3']['cvssV3']['vectorString']
  attack_vector = i['impact']['baseMetricV3']['cvssV3']['attackVector']
  attack_complexity = i['impact']['baseMetricV3']['cvssV3']['attackComplexity']
  privilege_required = i['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
  user_interaction = i['impact']['baseMetricV3']['cvssV3']['userInteraction']
  scope = i['impact']['baseMetricV3']['cvssV3']['scope']
  confidentiality_impact = i['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
  integrity_impact = i['impact']['baseMetricV3']['cvssV3']['integrityImpact']
  cvssv3_base_score = i['impact']['baseMetricV3']['cvssV3']['baseScore']
  severity = i['impact']['baseMetricV3']['cvssV3']['baseSeverity']
  published = i['publishedDate']
  last_modified = i['lastModifiedDate']

#  assigner = i['cve']['CVE_data_meta']['ASSIGNER']
#  assigner = i['cve']['CVE_data_meta']['ASSIGNER']
#  assigner = i['cve']['CVE_data_meta']['ASSIGNER']
#    print(cve,cpe)
#  reference = i['reference_data']['url']
#  print(cve,assigner,reference)
      
#	if ['Event']['Attribute']['type'] in 'vulnerability':
#                test=     
#  		cve=i['Event']['Attribute']['value']
  json={
  'CVE': str(cve),
  'Assigner': str(assigner),
  'Description': str(description),
#  'CPE': str(cpe),
  'CVSSV3_Vector_String': str(cvssv3_vector_string),
  'Attack_Vector': str(attack_vector),
  'Attack_Complexity': str(attack_complexity),
  'Privilege_Required': str(privilege_required),
  'User_Interaction': str(user_interaction),
  'Scope': str(scope),
  'Confidentiality_Impact': str(confidentiality_impact),
  'Integrity_Impact': str(integrity_impact),
  'CVSSV3_Base_Score': float(cvssv3_base_score),
  'Severity': str(severity),
  'Published': str(published),
  'Product': 'AWS',
  'Last_Modified': str(last_modified)
  }
  print(json)
  r_post=requests.post(url_post, headers=headers_post, verify=False, json=json)
#  r_post=requests.post(url_post, auth=('user', 'password'), headers=headers_post, verify=False, json=json)
  print(r_post.status_code)


