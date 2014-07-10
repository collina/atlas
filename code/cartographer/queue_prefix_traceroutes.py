import pygeoip
import argparse
import random
import json
from netaddr import *

from common import RIPEAtlas

def main(args):
    
    GEOIP_ASN	= pygeoip.GeoIP('common/GeoIPASNum.dat')
    query_structure_measurement = {'type': 'traceroute', 'af': 4, 'is_oneoff': 'false', 'interval': 1800, 'is_public': 'false', 'resolve_on_probe': 'true', 'target': None, 'protocol': 'TCP', 'port': 80}
    query_structure_probes =  { 'requested': 1, 'type': 'area', 'value': None }
    measurement_data = {'definitions': [], 'probes': []}
    seen_asns, seen_names = set(), set()
    
    for prefix in args.file_in:
        if prefix.find('-') == -1:
            prefix_parsed = IPNetwork(prefix)
        else:
            ip_start, ip_end = prefix.split('-')
            all_ips = list(iter_iprange(ip_start, ip_end))
            prefix_parsed = cidr_merge(all_ips)[0]
        
        sampled_asn = GEOIP_ASN.org_by_addr( prefix_parsed.ip.format() )
        sampled_asn_number = sampled_asn.split()[0] if sampled_asn is not None else None
        sampled_asn_name = ' '.join(sampled_asn.split()[1:]).lower() if sampled_asn is not None else None
        
        if prefix_parsed.version == 4: # and prefix_parsed.prefixlen < 21 and sampled_asn_number not in seen_asns and sampled_asn_name not in seen_names:
            defined_query = query_structure_measurement.copy()
            for sampled_address in random.sample(prefix_parsed, 1):
                print str(sampled_address)
                defined_query['target'] = str(sampled_address)

            description = defined_query
            description['tag'] = args.tag
            
            defined_query['description'] = json.dumps(description)
            measurement_data['definitions'].append(defined_query)
            
            seen_asns.add(sampled_asn_number)
            seen_names.add(sampled_asn_name)
            
            print prefix_parsed, sampled_address, sampled_asn_number, sampled_asn_name
    
    for area in ["West", "North-East", "South-East", "North-Central", "South-Central"]:
        area_probe_query = query_structure_probes.copy()
        area_probe_query['value'] = area
        measurement_data['probes'].append(area_probe_query)

    query_structure_country =  { 'requested': 2, 'type': 'country', 'value': 'IQ' }
    measurement_data['probes'].append(query_structure_country)

    print measurement_data
    measurement = RIPEAtlas.Measurement(measurement_data, key = '388190e1-0ead-48f9-87b5-aff04853ce43')
    print("Queued Test #%i for %i Atlas Probes, waiting." % (measurement.id, probe_query['requested']))
    measurement_results = measurement.results(wait=True)
    print("Completed Test #%i" % (measurement.id))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                                     prog='Scamper to Pydot',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('file_in', type=argparse.FileType('r'), default=None, help='Scamper Warts File to Parse')
    parser.add_argument('tag', type=str, default=None, help='Scamper Warts File to Parse')
    
    args = parser.parse_args()
    main(args)