import logging
import definitions
import libatlas
import json
import numpy

class analyze():
    
    def __init__(self, results_files):
        self.measurement_list = []
        self.target = None
        self.data_type = None
        
        for results_file in results_files:
            try:
                raw_data = json.load(results_file)
            except ValueError as err:
                definitions.logger.error("Could not parse JSON, received %s", err)
                continue
            try:
                data_type  = raw_data[0]["type"]
                parsing_module = __import__("libatlas.parsers.%s_parser" % data_type, fromlist=[data_type])
            except ImportError as err:
                definitions.logger.error("Could not find parser for %s, received %s" % (data_type, err))
                continue
            parser = parsing_module.Parser()
            for one_measurement in raw_data:
                temporary_row = one_measurement.copy()
                temporary_row['_parsed'] = parser.load(one_measurement)
                self.measurement_list.append(temporary_row)
        
        self.data_type = data_type
        
        if data_type == 'dns':
            self.measurement_class = analyze_dns(self.measurement_list)
        if data_type == 'sslcert':
            self.measurement_class = analyze_sslcert(self.measurement_list)
        return None
    
    def setup(self, active_probes = None):
        self.active_probes = libatlas.build_active_probes(active_probes_file = active_probes)
    
    def consensus(self, all_measurements, active_probes = None, preset_consensus = None, expect_empty = False):
        if active_probes == None:
            active_probes = self.active_probes
        return self.measurement_class.consensus(all_measurements, active_probes, preset_consensus, expect_empty = expect_empty)
    
    def recommend(self, consensus, active_probes = None):
        if active_probes == None:
            active_probes = self.active_probes
        return self.measurement_class.recommend(consensus, active_probes)
    
    def consensus_map(self, consensus_topology, style = 'flat'):
        
        consensus_to_return = {}
        
        for consensus_state, consensus_state_probe_ids in consensus_topology.iteritems():
            for probe_id in consensus_state_probe_ids:
                if style == 'flat' and self.active_probes.has_key(probe_id):
                    if self.active_probes.has_key(probe_id) and self.active_probes[probe_id].has_key(u'Country Code'):
                        probe_country = self.active_probes[probe_id][u'Country Code']
                        if not (consensus_to_return.has_key(probe_country)):
                            consensus_to_return[probe_country] = {'out': set(), 'in': set(), 'empty': set(), 'error': set()}
                        consensus_to_return[probe_country][consensus_state].add(probe_id)
                elif style == 'cc_asn' and self.active_probes.has_key(probe_id):
                    
                    if self.active_probes[probe_id].has_key(u'IPv4 ASN'):
                        probe_asn = self.active_probes[probe_id][u'IPv4 ASN']
                    elif self.active_probes[probe_id].has_key(u'IPv6 ASN'):
                        probe_asn = self.active_probes[probe_id][u'IPv6 ASN']
                    else:
                        probe_asn = None
                    
                    probe_country = self.active_probes[probe_id][u'Country Code'] if self.active_probes[probe_id].has_key(u'Country Code') else None
                    
                    if probe_country is not None and probe_asn is not None:
                        if not (consensus_to_return.has_key(probe_country)):
                            consensus_to_return[probe_country] = {}
                        if not (consensus_to_return[probe_country].has_key(probe_asn)):
                            consensus_to_return[probe_country][probe_asn] = {'out': set(), 'in': set(), 'empty': set(), 'error': set()}
                            
                        consensus_to_return[probe_country][probe_asn][consensus_state].add(probe_id)
        return consensus_to_return
    
    def display_consensus(self, consensus_topology):
        
        consensus_mapped = self.consensus_map(consensus_topology, style='cc_asn')
        
        definitions.logger.info("-----------------------------------------------------------------------------------")
        definitions.logger.info("%15.13s  | %10s | %10s | %10s | %10s | %10s |" % ('Country Name', 'ASN', 'In', 'Out', 'Error', 'Empty'))
        definitions.logger.info("-----------------------------------------------------------------------------------")
        
        for country, country_results in consensus_mapped.iteritems():
            # definitions.logger.info("%15.13s %12s %12s %12s %12s %12s |" % (definitions.country_list[country], '', '', '', '', ''))
            for asn, asn_results in country_results.iteritems():
                if len(asn_results['out']) > 0 or len(asn_results['empty']) > 0 or len(asn_results['error']) > 0:
                    definitions.logger.info("%15.13s  | %10s | %10i | %10i | %10i | %10i |" % (definitions.country_list[country].decode('utf-8'), asn, len(asn_results['in']), len(asn_results['out']), len(asn_results['error']), len(asn_results['empty'])))
        definitions.logger.info("-----------------------------------------------------------------------------------")
        return consensus_mapped


class analyze_meta:
    def __init__(self, measurements):
        
        dataset_to_return = {}
        for one_measurement in measurements:
            if not (dataset_to_return.has_key(one_measurement['prb_id'])):
                dataset_to_return[one_measurement['prb_id']] = []
            if one_measurement.has_key('_parsed') and one_measurement['_parsed'] is not None:
                dataset_to_return[one_measurement['prb_id']] = {'destination': None, '_parsed': None, 'serial': None}
                dataset_to_return[one_measurement['prb_id']]['destination'] = one_measurement['dst_addr']
                dataset_to_return[one_measurement['prb_id']]['_parsed'] = one_measurement['_parsed']
                dataset_to_return[one_measurement['prb_id']]['serial'] = self.translate_answers(one_measurement['_parsed'])
        self.dataset = dataset_to_return
        return None
    def recommend(self, consensus_topology, active_probes):
        
        recommended_probes = set()
        probes_out_of_consensus = consensus_topology['out'] | consensus_topology['error'] | consensus_topology['empty']
        asns_of_interest = set([active_probes[probe_id][asn_key] for probe_id in probes_out_of_consensus for asn_key in [u'IPv4 ASN', u'IPv6 ASN'] if active_probes[probe_id].has_key(asn_key)])
        countries_of_interest = set([active_probes[probe_id][u'Country Code'] for probe_id in probes_out_of_consensus if active_probes[probe_id].has_key(u'Country Code')])
        
        for probe_id, probe_details in active_probes.iteritems():
            
            if probe_details.has_key(u'IPv4 ASN'):
                probe_asn = probe_details[u'IPv4 ASN']
            elif probe_details.has_key(u'IPv6 ASN'):
                probe_asn = probe_details[u'IPv6 ASN']
            else:
                probe_asn = None
            if probe_asn and probe_asn in asns_of_interest and probe_id not in consensus_topology['in'] and probe_id not in probes_out_of_consensus:
                recommended_probes.add(probe_id)
        definitions.logger.info("Recommended additional probes: %s" % (recommended_probes))
        return recommended_probes
    def consensus(self, all_measurements, active_probes, consensus_source = None, expect_empty = False):
        '''
            First We Find a Consensus Answer if Multi-Country, otherwise we rely on a fall back, either direct answer, inter ASN agreement or cross comparision from preselected sample of other country.
            consensus_template - dict - key:set(answer) - value: set(countries)
        '''
        consensus_template = {}
        
        if expect_empty == False:
            transnational_sample = len(set([active_probes[probe_id][u'Country Code'] for probe_id in all_measurements.keys() if active_probes[probe_id].has_key(u'Country Code') ])) > 1

            if transnational_sample == True:
                for probe_id, probe_measurements in all_measurements.iteritems():
                    if len(probe_measurements) > 0:
                        for probe_measurement in probe_measurements['serial']:
                            if not (consensus_template.has_key(probe_measurement)):
                                consensus_template[probe_measurement] = set()
                            if active_probes[probe_id].has_key(u'Country Code'):
                                consensus_template[probe_measurement].add(active_probes[probe_id][u'Country Code'])
            elif transnational_sample == False and consensus_source is None:
                for probe_id, probe_measurements in all_measurements.iteritems():
                    probe_asn = libatlas.get_asn(probe_id, active_probes)
                    if len(probe_measurements) > 0:
                        for probe_measurement in probe_measurements['serial']:
                            if not (consensus_template.has_key(probe_measurement)):
                                consensus_template[probe_measurement] = set()
                            if probe_asn is not None:
                                consensus_template[probe_measurement].add(probe_asn)
            elif transnational_sample == False and consensus_source is not None:
                definitions.logger.error("Not Yet Implemented")
            
            consensus_template_mean = numpy.mean([float(len(countries)) for countries in consensus_template.values()])
            
            consensus_hypothesis = [address for address, countries in consensus_template.iteritems() if len(countries) >= consensus_template_mean]
            definitions.logger.info("Hypothesis for valid %s answers based on a mean of %f is %s" % (self.data_type, numpy.asscalar(consensus_template_mean), consensus_hypothesis))
        
        consensus_topology = {'out': set(), 'in': set(), 'empty': set(), 'error': set()}
        
        for probe_id, probe_measurements in all_measurements.iteritems():
        
            if expect_empty == False:
                if len(probe_measurements) == 0:
                    # , str(self.get_hint(probe_measurements['destination'], error_type = 'unresponsive'))
                    consensus_topology['empty'].add(probe_id)
                    definitions.logger.debug("No Results %s %i" % (active_probes[probe_id][u'Country Code'], probe_id))
                else:
                    for probe_measurement in probe_measurements['serial']:
                        if not (probe_measurement in consensus_hypothesis):
                            consensus_topology['out'].add(probe_id)
                            definitions.logger.debug("Mismatch %s %i %s %s connecting to %s" % (active_probes[probe_id][u'Country Code'], probe_id, probe_measurement, str(self.get_hint(probe_measurements[u'_parsed'])), probe_measurements['destination']))
                    if not (probe_id in consensus_topology['out']):
                        consensus_topology['in'].add(probe_id)
            else:
                if len(probe_measurements) == 0:
                    consensus_topology['in'].add(probe_id)
                else:
                    for probe_measurement in probe_measurements['serial']:
                        consensus_topology['out'].add(probe_id)
                        definitions.logger.debug("Mismatch %s %i %s %s" % (active_probes[probe_id][u'Country Code'], probe_id, probe_measurement, str(self.get_hint(probe_measurements[u'_parsed']))))
        
        return consensus_topology

class analyze_dns(analyze_meta):
    data_type = 'dns'
    def translate_answers(self, parsed):
        dataset_to_return = []
        
        for dns_message in parsed:
            for answer in dns_message.answer:
                for answer_name in answer.to_rdataset():
                    dataset_to_return.append(str(answer_name))
        return dataset_to_return
    
    def get_hint(self, parsed):
        dataset_to_return = []
        
        for dns_message in parsed:
            for answer in dns_message.answer:
                for answer_name in answer.to_rdataset():
                    dataset_to_return.append(str(answer_name))
        return dataset_to_return
    
    def retrieve_target(self, information_cache):
        targets_to_return = {}
        for information_file in information_cache:
            information_dict = json.load(information_file)
            information_dict_description = json.loads(information_dict[u'description'])
            targets_to_return[information_dict_description[u'query_argument']] = information_dict_description
        return targets_to_return

class analyze_sslcert(analyze_meta):
    data_type = 'sslcert'
    def translate_answers(self, parsed):
        dataset_to_return = []
        
        for ssl_cert in parsed:
            dataset_to_return.append(str(ssl_cert.get_serial_number()))
        
        return dataset_to_return

    def get_hint(self, parsed, error_type = 'mismatch'):
        dataset_to_return = []
        
        if error_type == 'mismatch':
            for ssl_cert in parsed:
                data_line = "%s from %s" % (ssl_cert.get_subject().CN, str(ssl_cert.get_issuer().O))
                dataset_to_return.append(data_line)
        elif error_type == 'unresponsive':
            dataset_to_return = []
        return dataset_to_return

    def retrieve_target(self, information_cache):
        targets_to_return = {}
        for information_file in information_cache:
            information_dict = json.load(information_file)
            information_dict_description = json.loads(information_dict[u'description'])
            targets_to_return[information_dict_description[u'target']] = information_dict_description
        return targets_to_return
