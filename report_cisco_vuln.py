# -*- coding: utf-8 -*-
"""
Created on Tue Feb  2 21:45:22 2021

Com base no nome de um report o script faz a busca do ID e efetua o download do mesmo,
salvando o resultado tanto em csv no disco quanto em um dataframe para posterior processamento

@author: kb1a
"""

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
es = Elasticsearch(['http://elastic.howtoonline.com.br:9200'])
r = es.search(index="nvd-"+today+"", body={"size": 500, "query": {"match": {"Product": "CISCO IOS"}}})
#misp_url="http://stark"
#misp_key="wADgKpuZNLcBbFDcKlB6xqkGCUYOZFMU6e5UK3ta"
for i in r['hits']['hits']:
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
  url = "https://stark"
  key = "wADgKpuZNLcBbFDcKlB6xqkGCUYOZFMU6e5UK3ta"
  misp_verifycert = False
  misp = ExpandedPyMISP(url, key, misp_verifycert)
  event = MISPEvent()
  event.info = "Vulnerability Report - Platform: "+product+": "+severity+""
  event.distribution = "0"
  event.sharing_group_id = "2"
  event.analysis = "1"

  if(severity == "CRITICAL" or severity == "HIGH"):
    event.distribution = "4"
    event.sharing_group_id = "4"
    event.threat_level_id = "1"
    event.published = True
  else:
    event.threat_level_id = "2"
    event.published = False

  event.add_tag('tlp:green')
  event.add_tag('CVE')
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
  event = misp.add_event(event)
