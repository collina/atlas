import libatlas
import random
import json
import definitions

from common import RIPEAtlas

class measure():
    def __init__(self, max_probes_per_measurement = 500, active_probes = None, api_key = None):
        self.max_probes_per_measurement = max_probes_per_measurement
        self.query_structure_measurement = {
                    'dns' : {'type': 'dns', 'af': 4, 'is_oneoff': 'true', 'is_public': 'true', 'use_probe_resolver': 'true', 'recursion_desired': 'true', 'query_class': 'IN', 'query_type': 'A', 'query_argument': None},
                    'sslcert' : {'type': 'sslcert', 'af': 4, 'is_oneoff': 'true', 'is_public': 'true', 'resolve_on_probe': 'true', 'target': None, 'port': None},
                    'traceroute' : {'type': 'traceroute', 'af': 4, 'is_oneoff': 'true', 'is_public': 'true', 'resolve_on_probe': 'true', 'target': None, 'protocol': 'ICMP', 'port': None},
                }
        self.query_structure_probes = {'requested': None, 'type': 'probes', 'value': None}
        self.active_probes = libatlas.build_active_probes(active_probes_file = active_probes, style = 'cc_asn')
        self.api_key = api_key
    def get_chunks(self, arr, chunk_size = 10):
        return [arr[start:start+chunk_size] for start in range(0, len(arr), chunk_size)]
    
    def define_sample(self, target_countries = ['WW'], unit_sample = 'asn', samples_per_unit = 3, active_probes = None, exclude_probes = []):
        candidate_probes = {}
        returned_sample_set = []
        
        active_probes = self.active_probes or active_probes
        
        for probe_country, probe_asns in active_probes.iteritems():
            if (probe_country in target_countries) or (target_countries == ['WW'] and probe_country != 'UNKNOWN'):
                for probe_asn, probes in probe_asns.iteritems():
                    if not (candidate_probes.has_key(probe_asn)):
                        candidate_probes[probe_asn] = set()
                    
                    offline_probes = [probe_id for probe_id, probe_dict in probes.iteritems() if probe_dict['online'] is False]
                    clean_list = set(probes.keys()) - set(exclude_probes) - set(offline_probes)
                    
                    candidate_probes[probe_asn] |= clean_list
    
        for asn, probes in candidate_probes.iteritems():
            probes = list(probes)
            random.shuffle(probes)
            if samples_per_unit:
                returned_sample_set += probes[:samples_per_unit]
            else:
                returned_sample_set += probes
        return returned_sample_set
    
    def define_measurement_call(self, test, target, sample_set, defined_query = None, additional_arguments = {}):
        measurement_data = {'definitions': [], 'probes': []}
        
        if type(sample_set) == set:
            sample_set = list(sample_set)
        
        if defined_query == None:
            defined_query = self.query_structure_measurement[test].copy()
            
            if test == 'dns':
                defined_query['query_argument'] = target.lower()
            elif test == 'sslcert':
                defined_query['target'] = target.lower()
                defined_query['port'] = str(additional_arguments['port']) if additional_arguments.has_key('port') else str(443)
            elif test == 'traceroute':
                defined_query['target'] = target.lower()
                defined_query['port'] = str(additional_arguments['port']) if additional_arguments.has_key('port') else str(80)
    
        defined_query['description'] = json.dumps(defined_query)
        measurement_data['definitions'].append(defined_query)
        
        for probe_subset in self.get_chunks(sample_set, chunk_size = self.max_probes_per_measurement):
            
            probe_query = self.query_structure_probes.copy()
            probe_query['requested'] = len(probe_subset)
            probe_query['value'] = ','.join([str(p) for p in probe_subset])
            
            measurement_data['probes'].append(probe_query)
        return measurement_data
    
    def submit_ripe_request(self, measurement_data):
        test_information_to_return = {}
        if self.api_key == None:
            definitions.logger.error("Missing API Key, Cannot Continue.")
            return False
        measurement_data_probes = measurement_data['probes']
        for probe_fragement in measurement_data_probes:
            measurement_data['probes'] = [probe_fragement]
            measurement = RIPEAtlas.Measurement(measurement_data, key = self.api_key)
            definitions.logger.info("Queued Test #%i for %i Atlas Probes, waiting." % (measurement.id, probe_fragement['requested']))
            measurement_results = measurement.results(wait=True)
            definitions.logger.info("Completed Test #%i" % (measurement.id))
            test_information_to_return[measurement.id] = probe_fragement['value']

        return test_information_to_return
