'''
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

import libatlas

def main(args):
    
    '''
        Setup Application Variables and Universally Revelant Handlers
    '''
    
    MAX_PROBES_PER_MEASUREMENT = 499
    CACHE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cache/')
    
    cache_handler = libatlas.cache()
    cache_handler.setup(CACHE_PATH, api_key)

    '''
        Setup API Key Awareness
    '''
    
    api_key_expected_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'api_key.txt')
    if os.path.exists(api_key_expected_location) is True:
        api_key = open(api_key_expected_location, 'rb').readline().rstrip()
        libatlas.definitions.logger.info('Found API Key: %s' % api_key)
    else:
        libatlas.definitions.logger.error('Could not find API Key, expected at: %s' % api_key_expected_location)

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
        consensus_topology = action_class.consensus(action_class.measurement_class.dataset)
        
        if args.retest == True and args.resource_location == 'remote':
        
            recommended_probes = action_class.recommend(consensus_topology)
            query_structures = action_class.measurement_class.retrieve_target(information)
            
            for query_argument, query_structure in query_structures.iteritems():
                action_class_measure = libatlas.measure(max_probes_per_measurement = MAX_PROBES_PER_MEASUREMENT, active_probes = args.active_probes, api_key = api_key)
                ripe_api_call = action_class_measure.define_measurement_call(None, None, recommended_probes, defined_query = query_structure)
                action_class_measure.submit_ripe_request(ripe_api_call)

        elif args.retest == True and args.resource_location == 'local':
            libatlas.definitions.logger.error('Retesting not yet supported for local results')

        action_class.display_consensus(consensus_topology)
    elif args.action == 'measure':
        
        action_class = libatlas.measure(max_probes_per_measurement = MAX_PROBES_PER_MEASUREMENT, active_probes = args.active_probes, api_key = api_key)
        
        if args.db is not None:
            measurement_sample = action_class.define_sample_sqlite(args.db, samples_per_unit = args.size, target_countries = args.countries)
        else:
            measurement_sample = action_class.define_sample(samples_per_unit = args.size, target_countries = args.countries)

        ripe_api_call = action_class.define_measurement_call(args.test, args.target, measurement_sample)
        action_class.submit_ripe_request(ripe_api_call)
        
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Select RIPE Atlas probes.")
    parser.add_argument('--active-probes', dest="active_probes", type=argparse.FileType('r'), default=None)
    
    subparsers = parser.add_subparsers()
    
    parser_analyze = subparsers.add_parser('analyze', help='Look for Dissimiliarities in Results')
    parser_analyze.add_argument("--retest", action='store_true', default=False, help="Retest based on results")
    
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

    parser_measure.add_argument("-d", "--db", type=str, default=None, help="Use a Sqlite DB of Probes")
    parser_measure.add_argument("-c", "--countries", nargs='+', default=['WW'], help="Country code of interest.")
    parser_measure.add_argument("-s", "--size", type=int, default=None, help="Number of Probes Per ASN (default all probes)")
    parser_measure.set_defaults(action='measure')
    
    args = parser.parse_args()
    
    exit(main(args))
