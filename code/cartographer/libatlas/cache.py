import json
import os
import urllib2
import libatlas
import definitions

class cache():
    def __init__(self):
        self.cache_format = "atlas_cache-%s-measurement_id-%i.json"
        return None
    def setup(self, cache_path, api_key):
        self.cache_path = cache_path
        self.api_key = api_key
    def retrieve_files(self, measurement_ids, type = 'results'):
        results_to_return = []
        for measurement_id in measurement_ids:
            returned_local_existence = self.check_local_existence(measurement_id, type = type)
            if returned_local_existence is not False:
                definitions.logger.info("Found Cache for Measurement %s at Path: %s" % (measurement_id, returned_local_existence))
                results_to_return.append(returned_local_existence)
            else:
                definitions.logger.info("Missed Cache for Measurement %s." % (measurement_id))
                returned_remote_existence = self.check_remote_existence(measurement_id, type = type)
                if returned_remote_existence is not False:
                    results_to_return.append(returned_remote_existence)
        return results_to_return
    
    def check_local_existence(self, measurement_id, type = 'results'):
        expected_path = os.path.join(self.cache_path, self.cache_format) % (type, measurement_id)
        if os.path.exists(expected_path) == True:
            return open(expected_path, 'rb')
        return False
    def check_remote_existence(self, measurement_id, type = 'results'):
        
        try:
            if type == 'results':
                remote_url = 'https://atlas.ripe.net/api/v1/measurement/%s/result/?key=%s' % (measurement_id, self.api_key)
            elif type == 'information':
                remote_url = 'https://atlas.ripe.net/api/v1/measurement/%s/?key=%s' % (measurement_id, self.api_key)
            
            remote_req = urllib2.urlopen(remote_url)
            remote_results = remote_req.read()
            results_parsed = json.loads(remote_results)
            
            cache_output_path = os.path.join(self.cache_path, self.cache_format) % (type, measurement_id)
            
            with open(cache_output_path, 'wb') as cache_output:
                json.dump(results_parsed, cache_output)
            
            return open(cache_output_path, 'rb')
        except Exception as err:
            definitions.logger.info("Error Retrieving Remote Active Probes File: %s" % err)
            return False
        
        return False
