import mechanize
import json
import base64
import socket
import yaml
import OpenSSL
import dns.message, dns.query, dns.message

from datetime import datetime

API_KEY = '5c5625a8-da98-4a66-98c8-64c3e85f2e6c'

class MeasurementRecord:
    def __init__(self, type, timestamp = None, probe = None, source = None, destination = None, failure = None, result = None):
        self.timestamp = timestamp
        self.source = source
        self.destination = destination
        self.probe = probe
        self.failure = failure
        self.result = result

class AtlasMeasurement:
    def __init__(self, identifier, type = 'file'):
        '''
            @param identifier: measurement id or file name
            @param type: 'file' for local json or 'remote' for query against RIPE API
        '''
        self.measurements = {}
        if type == 'remote':
            remote_url = 'https://atlas.ripe.net/api/v1/measurement/%s/result/?key=%s' % (identifier, API_KEY)
            remote_req = mechanize.Browser()
            remote_results = remote_req.open(remote_url).read()
            results_parsed = json.loads(remote_results)
        elif type == 'file':
            local_req = open(identifier, 'rb').read()
            results_parsed = json.loads(local_req)
        if results_parsed:
            for record_number, record_measurement in enumerate(results_parsed):
                if record_measurement['type'] == 'sslcert':
                    self.measurements[record_number] = self.parse_sslcert(record_measurement)
                elif record_measurement['type'] == 'traceroute':
                    self.measurements[record_number] = self.parse_traceroute(record_measurement)
                elif record_measurement['type'] == 'dns':
                    self.measurements[record_number] = self.parse_dns(record_measurement)
        return None
    def parse_sslcert(self, record_measurement):
        ''' 
            @returns destination: hostname of measurement
            @returns results: list of X509 objects
        '''
        returned_measurement = MeasurementRecord('sslcert', timestamp = datetime.fromtimestamp(int(record_measurement['timestamp'])), source = record_measurement['from'], destination = record_measurement['dst_name'])
        if 'err' in record_measurement:
            returned_measurement.failure = record_measurement['err']
        elif 'cert' in record_measurement:
            returned_measurement.results = [OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert) for cert in record_measurement['cert']]
        return returned_measurement
    def parse_traceroute(self, record_measurement):
        returned_measurement = MeasurementRecord('traceroute', timestamp = datetime.fromtimestamp(int(record_measurement['timestamp'])), source = record_measurement['from'])
        if 'dst_addr' in record_measurement:
            returned_measurement.destination = record_measurement['dst_addr']
        elif 'addr' in record_measurement:
            returned_measurement.destination = record_measurement['addr']
        temporary_route_list = {}
        for r in record_measurement['result']:
            r['hop'] = int(r['hop'])
            temporary_route_list[r['hop']] = [ (h['from'], h['ttl']) if 'from' in h else (None, None) for h in r['result']]
        returned_measurement.results = temporary_route_list
        return returned_measurement
    def parse_dns(self, record_measurement):
        returned_measurement = MeasurementRecord('dns', timestamp = datetime.fromtimestamp(int(record_measurement['timestamp'])), source = record_measurement['from'])
        if 'dst_addr' in record_measurement:
            returned_measurement.destination = record_measurement['dst_addr']
        elif 'addr' in record_measurement:
            returned_measurement.destination = record_measurement['addr']
        try:
            temporary_dns_records, temporary_question = {}, None
            if 'resultset' in record_measurement:
                for dns_answer_raw in record_measurement['resultset']:
                    if 'result' in dns_answer_raw:
                        dns_answer_decoded = dns.message.from_wire(base64.b64decode(dns_answer_raw['result']['abuf']))
                        if isinstance(dns_answer_decoded, dns.message.Message):
                            for rrset in dns_answer_decoded.question:
                                temporary_question = (rrset.name, rrset.rdtype)
                            for dns_answer_decoded_answer in dns_answer_decoded.answer:
                                temporary_dns_records[temporary_question] = dns_answer_decoded_answer.items
                    elif 'error' in dns_answer_raw:
                        if returned_measurement.failure is None:
                            returned_measurement.failure = {}
                        returned_measurement.failure[dns_answer_raw['dst_addr']] = dns_answer_raw['error']
            elif 'result' in record_measurement:
                dns_answer_decoded = dns.message.from_wire(base64.b64decode(record_measurement['result']['abuf']))
                if isinstance(dns_answer_decoded, dns.message.Message):
                    for rrset in dns_answer_decoded.question:
                        temporary_question = (rrset.name, rrset.rdtype)
                for dns_answer_decoded_answer in dns_answer_decoded.answer:
                    temporary_dns_records[temporary_question] = dns_answer_decoded_answer.items
            else:
                raise dns.query.BadResponse()
            returned_measurement.results = temporary_dns_records
        except dns.query.BadResponse as caught_exception:
            returned_measurement.failure = caught_exception
        return returned_measurement
