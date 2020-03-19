#!/usr/bin/env python

# source: https://blog.security-center.io/transform-your-passive-defense-into-active-defense-with-modsecurity-and-misp/

### Library
import urllib3, re, json, requests, time, sys, datetime, smtplib
from pymisp import PyMISP
from datetime import datetime
import os

# Disable TLS warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default Variables
ioc_category = "Network activity"


### Functions
# Date to Epoch
def convertToEpoch(date):
     pattern = '%Y-%m-%d'
     return int(time.mktime(time.strptime(date, pattern)))

# Push to Misp
def pushtoMISP(ioc_value):
     # Variable: MISP URL, Cert, Key
     misp_url = 'https://misp.security-center.io/'
     misp_verifycert = False
     misp_key = "**************************************"


     # MISP connection
     misp = PyMISP(misp_url, misp_key, True, 'json')

     #date = "2018-02-28"
     i = datetime.now()
     date = i.strftime('%Y-%m-%d')

     # Set the event name
     Event_name = "ModSecurity - "+date+" - Honeypot"

     # Prepare MISP attribute
     misp_attributes = []
     ioc_datetime = str(convertToEpoch(date))
     comments = " "
     misp_attribute = {
         'category': ioc_category, 'type': 'ip-dst', 'value': ioc_value, 'distribution': '0',
         'to_ids': True, 'comment': comments , 'timestamp': ioc_datetime
     }
     misp_attributes.append(misp_attribute)

     # Prepare MISP event
     misp_event = {
         'Event': {
             'info': Event_name, 'date': date, 'distribution': '0', 'threat_level_id': '1',
             'analysis': '2', 'Tag': [
                 {'name': 'ModSecurity'},
                 {'name': 'AUTO'}
              ],
             'Attribute': misp_attributes
         }
     }

     # Insert Event + Attribute to MISP
     misp_event_added = misp.add_event(misp_event)
     # Publish (/!\ Bring in production)
     misp.publish(misp_event_added)


### Main
def main():
     global ip_to_add
     ip_to_add=str(os.environ["ATTACKER"])
     pushtoMISP(ip_to_add)

if __name__ == "__main__":
     main()
