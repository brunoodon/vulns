#import pd
from pymisp import (MISPEvent, MISPSighting, MISPTag, MISPOrganisation, MISPObject)
from pymisp import MISPEvent, MISPObject, PyMISP, ExpandedPyMISP, MISPSharingGroup
import argparse
import csv
#import pandas as pd
import requests
import io
import os
import time
import datetime
import json
#import warnings
today=str(datetime.date.today())

from elasticsearch import Elasticsearch
es = Elasticsearch(['http://elastisearch_host:9200'])
#es = Elasticsearch(['http://elastisearch_host:9200'], verify_certs=False)
r = es.search(index="nvd-"+today+"", body={"size": 500, "query": {"match": {"Product": "NGINX"}}})
#res = es.search(index="report-results-"+today+"", body={"query": {"match_all": {}}})
#json_data=json.loads(r)
#print(r)
#print(json.loads(result))
misp_url="https://misp_site"
misp_key="misp_authkey"
misp_verifycert = False
for i in r['hits']['hits']:
#  print(i["_source"])
  assigner = i['_source']['Assigner']
  attack_complexity = i["_source"]["Attack_Complexity"]
  attack_vector = i["_source"]["Attack_Vector"]
  cve = i["_source"]["CVE"]
  cvssv3_base_score = i["_source"]["CVSSV3_Base_Score"]
  cvssv3_vector_string = i["_source"]["CVSSV3_Vector_String"]
  confidentiality_impact = i["_source"]["Confidentiality_Impact"]
  description = i["_source"]["Description"]
  integrity_impact = i["_source"]["Integrity_Impact"]
  last_modified = i["_source"]["Last_Modified"]
  privilege_required = i["_source"]["Privilege_Required"]
  product = i["_source"]["Product"]
  published = i["_source"]["Published"]
  scope = i["_source"]["Scope"]
  severity = i["_source"]["Severity"]
  user_interaction = i["_source"]["User_Interaction"]
  url = "https://misp_site"
  key = "misp_authkey"
  misp_verifycert = False
  misp = ExpandedPyMISP(url, key, misp_verifycert)
  event = MISPEvent()
  event.info = "Vulnerability Report - Platform: "+product+": "+severity+""
#	      event.publish = True
#	      self.sharing_group_id = "2"
#	      self.sharing_group_name = "CKN"
	      #event.sharing_group_id = "2"
#	      event.sharing_group_id = "1"
#	      sharing_group_uuid = "73c83703-3e60-4c5c-91d8-776ce30fae86"
#	      event.sharing_group.name = "CKN"
  event.distribution = "0"
#	      event.sharing_group_id = "1"
#	      event.sharing_group_name = "CKN"
#	      event.sharing_group_uuid = "CKN
  event.analysis = "1"

  if(severity == "CRITICAL" or severity == "HIGH"):
    event.threat_level_id = "1"
    event.published = True
    event.distribution = "2"
#    event.sharing_group_id = "1"
  else:
    event.threat_level_id = "2"
    event.published = False

  event.add_tag('tlp:white')
  event.add_tag('CVE')
#  for a in cve.split(","):
#    event.add_attribute('vulnerability', str(a))

#  event.add_attribute('other', str(assigner), comment="Assigner", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(attack_complexity), comment="Attack Complexity", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(attack_vector), comment="Attack Vector", disable_correlation=True, to_ids=False)
  event.add_attribute('vulnerability', str(cve), comment="CVE", disable_correlation=False, to_ids=False)
  event.add_attribute('other', str(cvssv3_base_score), comment="CVSSV3 Base Score", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(cvssv3_vector_string), comment="CVSSV3 Vector String", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(confidentiality_impact), comment="Confidentiality Impact", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(description), comment="Description", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(integrity_impact), comment="Integrity Impact", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(last_modified), comment="Last Modified", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(privilege_required), comment="Privilege Required", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(product), comment="Platform", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(published), comment="Published", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(scope), comment="Scope", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(severity), comment="Severity", disable_correlation=True, to_ids=False)
  event.add_attribute('other', str(user_interaction), comment="User Interaction", disable_correlation=True, to_ids=False)
#  if(cvssv3_base >= 8):
  event = misp.add_event(event)
#  print(event)
