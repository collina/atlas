'''
    To-Do:
    Add a tag to measurement description that links fragmented queries
'''

import re
import random
import argparse
import json
import sys
import os
import sqlite3
import logging
import time

import libatlas

class CartographyState:
    def __init__(self, db_path):
        self.db_conn = sqlite3.connect(db_path)
        self.db_cur = self.db_conn.cursor()

    def blacklist_probes(self, probe_list, data_type, reason = ''):
        
        self.db_cur.execute('CREATE TABLE IF NOT EXISTS blacklist (probe_id int, data_type varchar, reason varchar, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')

        for probe_id in probe_list:
            self.db_cur.execute('INSERT INTO blacklist (probe_id, data_type, reason) VALUES(?,?,?)', (probe_id, data_type, reason))
        
        self.db_conn.commit()
    
    def retrieve_blacklist(self, data_type = None):
        backlist_to_return = set()
        conditional = ''
        
        if data_type is not None:
            conditional = " WHERE data_type = '%s'" %data_type
        self.db_cur.execute("SELECT probe_id, data_type, reason FROM blacklist %s" % (conditional))
        sql_dataset = self.db_cur.fetchall()

        for probe_id, data_type, reason in sql_dataset:
            backlist_to_return.add(probe_id)

        return backlist_to_return

    def store_test_information(self, measurements, test, target):
        
        timestamp = int(time.time())
        
        self.db_cur.execute('CREATE TABLE IF NOT EXISTS measurements (measurement_id int, probe_ids varchar, data_type varchar, target varchar, timestamp INT)')
        
        for measurement_id, probe_list in measurements.iteritems():
            self.db_cur.execute('INSERT INTO measurements (measurement_id, probe_ids, data_type, target, timestamp) VALUES(?,?,?,?,?)', (measurement_id, probe_list, test, target, timestamp))
        
        self.db_conn.commit()
        return True

    
def main(args):
    
    '''
        Setup API Key Awareness
    '''
    
    api_key_expected_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'api_key.txt')
    if os.path.exists(api_key_expected_location) is True:
        api_key = open(api_key_expected_location, 'rb').readline().rstrip()
        logging.debug('Found API Key: %s' % api_key)
    else:
        logging.error('Could not find API Key, expected at: %s' % api_key_expected_location)


    sqlite3_state_path = args.db or "state.db3"

    application_state = CartographyState(sqlite3_state_path)

    '''
        Setup Application Variables and Universally Revelant Handlers
    '''
    
    MAX_PROBES_PER_MEASUREMENT = 499
    CACHE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cache/')
    
    cache_handler = libatlas.cache()
    cache_handler.setup(CACHE_PATH, api_key)

    if args.verbose == True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    '''
        Determine Activity
    '''
    if args.action == 'analyze':
        
        if args.resource_location == 'remote':
            results = cache_handler.retrieve_files(args.results)
            information = cache_handler.retrieve_files(args.results, type = 'information')
        else:
            results = args.results
        
        action_class = libatlas.analyze(results)
        action_class.setup(active_probes = args.active_probes)
        consensus_topology = action_class.consensus(action_class.measurement_class.dataset, expect_empty = args.empty)
        
        if args.rebase == True:
            application_state.blacklist_probes(consensus_topology['empty'], action_class.data_type, 'empty')
        
        if args.retest == True and args.resource_location == 'remote':
        
            recommended_probes = action_class.recommend(consensus_topology)
            query_structures = action_class.measurement_class.retrieve_target(information)
            
            for query_argument, query_structure in query_structures.iteritems():
                action_class_measure = libatlas.measure(max_probes_per_measurement = MAX_PROBES_PER_MEASUREMENT, active_probes = args.active_probes, api_key = api_key)
                ripe_api_call = action_class_measure.define_measurement_call(None, None, recommended_probes, defined_query = query_structure)
                action_class_measure.submit_ripe_request(ripe_api_call)

        elif args.retest == True and args.resource_location == 'local':
            libatlas.logger.error('Retesting not yet supported for local results')

        action_class.display_consensus(consensus_topology)
        
    elif args.action == 'measure':
        
        action_class = libatlas.measure(max_probes_per_measurement = MAX_PROBES_PER_MEASUREMENT, active_probes = args.active_probes, api_key = api_key)
        
        blacklisted_probes = application_state.retrieve_blacklist(args.test) if args.blacklist else []
        
        measurement_sample = action_class.define_sample(samples_per_unit = args.size, target_countries = args.countries, exclude_probes = blacklisted_probes)
        
        logging.info("Conducting tests over %i probes." % len(measurement_sample))
        ripe_api_call = action_class.define_measurement_call(args.test, args.target, measurement_sample)
        measurements = action_class.submit_ripe_request(ripe_api_call)
        application_state.store_test_information(measurements, args.test, args.target)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Select RIPE Atlas probes.")
    parser.add_argument('--active-probes', dest="active_probes", type=argparse.FileType('r'), default=None)
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument("--db", type=str, default=None, help="Path Database that maintains Cartography State.")
    
    subparsers = parser.add_subparsers()
    
    parser_analyze = subparsers.add_parser('analyze', help='Look for Dissimiliarities in Results')
    parser_analyze.add_argument("--retest", action='store_true', default=False, help="Retest based on results.")
    parser_analyze.add_argument("--rebase", action='store_true', default=False, help="Sets a blacklist for false or failed results in the Sqlite database.")
    parser_analyze.add_argument("--empty", action='store_true', default=False, help="Expect an empty response.")
    
    parser_analyze_type_subparsers = parser_analyze.add_subparsers()
    parser_analyze_type_subparsers_remote = parser_analyze_type_subparsers.add_parser('remote', help='Look for Dissimiliarities in Results')
    parser_analyze_type_subparsers_remote.add_argument('results', nargs='+', type=int)
    parser_analyze_type_subparsers_remote.set_defaults(resource_location='remote')

    parser_analyze_type_subparsers_local = parser_analyze_type_subparsers.add_parser('local', help='Look for Dissimiliarities in Results')
    parser_analyze_type_subparsers_local.add_argument('results', nargs='+', type=argparse.FileType('r'), default=sys.stdin)
    parser_analyze_type_subparsers_local.set_defaults(resource_location='local')
    
    parser_analyze.set_defaults(action='analyze')
    
    parser_measure = subparsers.add_parser('measure', help='Queue a Measurement.')
    parser_measure.add_argument("test", type=str, default=None, choices=['sslcert', 'ping', 'dns', 'traceroute'], help="Test to Conduct")
    parser_measure.add_argument("target", type=str, default=None, help="Target to Test Against.")

    parser_measure.add_argument("--blacklist", action='store_true', default=False, help="Use a blacklist from Cartography state database")
    parser_measure.add_argument("-c", "--countries", nargs='+', default=['WW'], help="Country code of interest.")
    parser_measure.add_argument("-s", "--size", type=int, default=None, help="Number of Probes Per ASN (default all probes)")
    parser_measure.set_defaults(action='measure')
    
    args = parser.parse_args()
    
    exit(main(args))
