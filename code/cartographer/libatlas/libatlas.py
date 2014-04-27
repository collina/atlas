import os
import logging
import parsers
import json
import re
import urllib2
import numpy
import random

import sqlite3
import OpenSSL
from common import RIPEAtlas

import definitions
import cache

def extract_active_probes_number(url):
    """
        Extract the ASN from the following URL:
        <a href='https://stat.ripe.net/AS5719' target='_blank'>5719</a>
        """
    
    pattern = ".*<a href='[^']*' target='_blank'>([^<]*)</a>.*"
    
    match = re.match(pattern, url)
    
    if match is not None:
        return match.group(1)
    return None


def build_active_probes(active_probes_file = None, style = 'flat'):
    dataset_to_return = {}
    
    if active_probes_file:
        try:
            active_probes = json.load(active_probes_file)
        except ValueError as err:
            return False
    else:
        definitions.logger.info("Retrieving Remote Active Probes File.")
        response = urllib2.urlopen(definitions.active_probes_url)
        json_blurb = response.read()
        active_probes = json.loads(json_blurb)
    
    for probe in active_probes:
        
        probe_dict = dict([(probe[3][i], probe[3][i+1]) for i, value in enumerate(probe[3]) if i % 2 == 0])
        
        for fixable_key in [u'IPv4 Prefix', u'IPv4 ASN', u'IPv6 Prefix', u'IPv6 ASN']:
            if probe_dict.has_key(fixable_key):
                probe_dict[fixable_key] = extract_active_probes_number(probe_dict[fixable_key])
        
        if style == 'flat':
            dataset_to_return[probe_dict[u'Probe ID']] = probe_dict
        elif style == 'cc_asn':
            
            probe_country = probe_dict[u'Country Code'] if probe_dict.has_key(u'Country Code') else 'UNKNOWN'
            
            if probe_dict.has_key(u'IPv4 ASN'):
                probe_asn = probe_dict[u'IPv4 ASN']
            elif probe_dict.has_key(u'IPv6 ASN'):
                probe_asn = probe_dict[u'IPv6 ASN']
            else:
                probe_asn = 'UNKNOWN'
            
            if not (dataset_to_return.has_key(probe_country)):
                dataset_to_return[probe_country] = {}
            if not (dataset_to_return[probe_country].has_key(probe_asn)):
                dataset_to_return[probe_country][probe_asn] = {}
            dataset_to_return[probe_country][probe_asn][probe_dict[u'Probe ID']] = probe_dict
    
    return dataset_to_return
