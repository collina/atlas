#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright (C) 2013 CDA

'''
    
	--------------------
	About
	--------------------
	Networking monitoring firms have pretty tools to collect and
	parse data on routes and performance, why shouldn't we?
	
	Author: Collin Anderson
	Email: collin@averysmallbird.com
	Version: 1.0-pre
	--------------------
	Datasource
	--------------------
    
	We use scamper for preparation, it's pretty cool and available in repos.
	
	e.g. scamper -p 200 -c "trace -P TCP -d 80 -g 3 -w 3 -f 2" -O warts -o outfile infile
    
	--------------------
	License (BSD 2-Clause, Thanks for Caring)
	--------------------
	Copyright (c) 2013, Collin Anderson
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or
	without modification, are permitted provided that the following
	conditions are met:
	
	(1) Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.
	
	(2) Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following disclaimer in
	the documentation and/or other materials provided with the
	distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
	USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
	AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
	LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
	ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
	
    
	--------------------
	TODO
	--------------------
	* Add Better Logging
	* Add Attribution
	* Tighter scamper integration?!
	
    '''

import argparse
import logging
import subprocess
import re
import pydot
import pygeoip
from matplotlib import pyplot
import logging
import json
import libatlas.parsers.traceroute_parser
import random

from datetime import datetime
from netaddr import IPSet, IPAddress

def main(args):
    
    graph = pydot.Dot(graph_type='digraph', rankdir = 'LR', ranksep = '2', nodesep = '.1', model = "circuit")
    logging.info(" SUPER SECRET BHK CODE. NO PENGUINS ALLOWED. ")
    parser = libatlas.parsers.traceroute_parser.Parser()
    routes, mask = [], []
    
    private = IPSet(['10.0.0.0/8', '172.16.0.0/12', '192.0.2.0/24', '192.168.0.0/16', '239.192.0.0/14', '100.64.0.0/10', '198.18.0.0/15'])
    reserved = IPSet(['225.0.0.0/8', '226.0.0.0/7', '228.0.0.0/6', '234.0.0.0/7', '236.0.0.0/7', '238.0.0.0/8', '240.0.0.0/4'])
    unavailable = reserved | private
    
    destination_address = None
    filter_country = 'ir'
    graph_start = datetime.strptime('2014-04-07 18:00', '%Y-%m-%d %H:%M')
    graph_end = datetime.strptime('2015-04-07 20:00', '%Y-%m-%d %H:%M')
#    graph_start = datetime.strptime('2014-03-21 2:00', '%Y-%m-%d %H:%M')
#    graph_end = datetime.strptime('2014-03-21 3:00', '%Y-%m-%d %H:%M')

#    graph_start = datetime.strptime('2014-03-22 2:00', '%Y-%m-%d %H:%M')
#    graph_end = datetime.strptime('2014-03-22 3:00', '%Y-%m-%d %H:%M')

#    interesting_paths = [13459, 13459, 10916, 10916, 168, 168, 173,    10096, 10184]

    #  12889, 12889, 13930, 13930, 173, 11473, 11473, 3827, 3827, 244, 244, 3837, 3837, 11024, 11024, 3861, 3861, 13590, 13590, 11043, 11043, 11047, 11047, 3880, 3880, 11063, 11063, 11066, 11066, 11071, 11071, 14680, 14680, 2917, 2917, 3945, 3945, 12139, 12139, 3959, 3959, 3960, 3960, 462, 462, 165, 165, 11751, 11751, 10228, 10228
    # , 173, 244, 2843, 2917, 343, 3719, 3791, 3827, 3857, 3861, 3880, 3958, 3960, 4440, 4756, 482
    
    asn_locations = {'destination': ['destination'], 'domestic': set(), 'start' : set(), 'drops': []}
    
    for results_file in args.file_in:
        for raw_data in json.load(results_file):
            timestamp = datetime.fromtimestamp(int(raw_data['timestamp']))
            if (timestamp > graph_start and timestamp < graph_end) and raw_data.has_key('dst_addr'): #and raw_data[u'prb_id'] in interesting_paths
                if destination_address == None:
                    destination_address = raw_data['dst_addr']
                parsed_path = parser.load(raw_data)
                start, end  = raw_data['src_addr'], raw_data['dst_addr']
                print start, end
                temporary_route = []
                
                if parsed_path is not None:
                    for hop, packets in parsed_path.iteritems():
                        if temporary_route == [] and filter_country is not None and packets[0][0] is not None:
                            lookup_cc = GEOIP_CC.country_code_by_addr(packets[0][0])
                            if lookup_cc is not None and lookup_cc.lower() != filter_country:
                                break
                        
                        for (address, rtt) in packets:
                            if address is not None and IPAddress(address) not in unavailable:
                                lookup_cc = GEOIP_CC.country_code_by_addr(address)
                                if destination_address == address:
                                    asn, label = "destination", "Destination (%s)" % address
                                else:
                                    asn, label = lookup_asn(address)
                                    if asn is not None:
                                        if lookup_cc.lower() == filter_country and len(temporary_route) > 0:
                                            asn_locations['domestic'].add(asn)
                                        elif len(temporary_route) == 0 and lookup_cc.lower() == filter_country:
                                            asn_locations['start'].add(asn)
                                if args.minimal == True and asn is not None and (len(temporary_route) == 0 or temporary_route[-1][0] != asn):
                                    temporary_route.append( (asn, label) )
                                    break
                                elif args.minimal == False:
                                    temporary_route.append(address)
                                    break
                routes.append(temporary_route)
    
    if args.sample is not None:
        random.shuffle(routes)
        routes = routes[:args.sample]
    print routes
    # Now I should have an awesome traceroutes dicts
    nodes, asn_locations = traceroutes_to_nodes(graph, routes, mask, minimal = args.minimal, asn_locations = asn_locations) # create all nodes
    nodes = traceroutes_to_edges(graph, routes, mask, nodes, minimal = args.minimal, asn_locations = asn_locations) # create all nodes
    graph.write_png(args.file_out)
    #
    #    if args.format == 'dot' or args['format'] == 'raw':
    #        graph.write_raw(args['file_out'])
    #    elif args['format'] == 'svg':
    #        graph.write_svg(args['file_out'])
    #    elif args['format'] == 'png' or args['format'] is None:
    #        graph.write_png(args['file_out'])
    
    return None # superstition
#

def lookup_asn(node):
    lookup = GEOIP_ASN.org_by_addr(node)
    
    if lookup is not None:
        if len(lookup.split(' ', 1)) > 1:
            (asn, label) = lookup.split(' ', 1)
        elif len(lookup.split(' ', 1)) is 1:
            (asn, label) = (lookup, '')
        else:
            (asn, label) = (None, 'Error')
    else:
        (asn, label) = (None, 'Private')
    return asn, label

def traceroutes_to_nodes(graph, routes = {}, mask = {}, minimal = False, asn_locations = None):
    global GEOIP_ASN, COLORS, COLOR_SE
    
    nodes	= {}
    cluster	= {}
    mask_asn = {}
    membership = []
    start_asns = []
    
    node_style = {
        'style' : "filled, rounded",
        'shape' : "rect",
        'nodesep' : 'auto',
        'width' : "auto",
        'width_end' : '2'
    }
    
    for trace in routes:
        for node in trace:
            if node not in nodes and node is not None:
                
                if minimal == False:
                    asn, asn_name = lookup_asn(node)
                    asn_label =  "%s (%s)" % (asn_name, asn)
                    label = node if node not in mask else "Masked"
                    name = node if node not in mask else "masked-" + str(mask.index(node))
                    cluster_key = asn or None
                else:
                    asn, asn_name = node[0], node[1]
                    label = asn_label =  "%s (%s)" % (asn_name, asn)
                    name = asn if node not in mask else "masked-" + str(mask.index(node))
                    cluster_key = [associations for associations in ['domestic', 'start', 'destination'] if asn in asn_locations[associations]]
                    cluster_key = cluster_key[0] if len(cluster_key) > 0 else 'frontier'
                
                if node == trace[-1] and asn not in asn_locations['destination']:
                    asn_locations['drops'].append(asn)
                if cluster_key not in cluster and cluster_key is not None:
                    if minimal == False:
                        cluster[cluster_key] = pydot.Cluster(cluster_key, style=node_style['style'], nodesep=node_style['nodesep'], width=node_style['width'], shape= node_style['shape'], label = asn_label) #, style="invis")
                    else:
                        cluster[cluster_key] = pydot.Cluster(cluster_key, style="invis")
                
                if node == trace[0]:
                    label = 'Start'
                nodes[ name ] = pydot.Node(name, style=node_style['style'], nodesep=node_style['nodesep'], width=node_style['width'], shape= node_style['shape'], label = label)
                
                if cluster_key is not None:
                    cluster[cluster_key].add_node(nodes[ name ])
                else:
                    graph.add_node(nodes[ name ])

    for asn in set(asn_locations['drops']):
        if asn in asn_locations['domestic'] or asn in asn_locations['start']:
            print asn, 'dropped', asn_locations['drops'].count(asn), 'times'
    for name, node in nodes.iteritems():
        if name in asn_locations['drops']:
            node.set("xlabel", "%i routes end here" % (asn_locations['drops'].count(name)))
    if minimal == False:
        more_structured(graph, cluster, routes, minimal = minimal, asn_locations = asn_locations)
    else:
        for cluster_key in cluster:
            graph.add_subgraph(cluster[cluster_key])
        more_simple(nodes, asn_locations = asn_locations)
    return nodes, asn_locations

def traceroutes_to_edges(graph, routes = {}, mask = {}, nodes = {}, minimal = False, asn_locations = None):
    global GEOIP_ASN, COLORS, COLOR_SE
    
    if minimal is False:
        edge_style = {
            'arrowhead' : "normal",
            'arrowsize' : "auto",
        }
    else:
        edge_style = {
            'arrowhead' : "open",
            'arrowsize' : ".5",
        }
    for trace in routes:
        unresp_filter = {'last_id': 0, 'skipped': 0}
        for item in range(len(trace)):
            if item != 0:
                label	= '* (%s)' % ( unresp_filter['skipped']) if unresp_filter['skipped'] is not 0 else ''
                line	= "#666666" if unresp_filter['skipped'] is not 0 else "#333333"
                arrow	= "empty" 	if unresp_filter['skipped'] is not 0 else "normal"
                
                if minimal == False:
                    name_1 = trace[unresp_filter['last_id']] if trace[unresp_filter['last_id']] not in mask else "masked-" + str(mask.index( trace[unresp_filter['last_id']]))
                    name_2 = trace[item] if trace[item] not in mask else "masked-" + str(mask.index(trace[item]))
                else:
                    name_1 = trace[unresp_filter['last_id']][0] if trace[unresp_filter['last_id']] not in mask else "masked-" + str(mask.index( trace[unresp_filter['last_id']]))
                    name_2 = trace[item][0] if trace[item][0] not in mask else "masked-" + str(mask.index(trace[item]))
                
                constraint = "true"
                
                edge = pydot.Edge(  nodes[name_1], nodes[name_2], arrowhead = edge_style['arrowhead'], arrowsize = edge_style['arrowsize'], color = line, constraint = constraint, penwidth = "1")
                graph.add_edge(edge)
                # logging.info( "Edge %s (%s, %s), skipped: %s", item, trace[unresp_filter['last_id']], trace[item], unresp_filter['skipped'] )
                
                unresp_filter['skipped'] = 0
                unresp_filter['last_id'] = item
    
    return graph

def more_simple(nodes, asn_locations = None):
    
    for name, node in nodes.iteritems():
        if name in asn_locations['destination']:
            node.set("shape", "rect")
            node.set("fillcolor", "#C9A9CD")
        elif name in asn_locations['start']:
            node.set("fillcolor", "#B1D7BF")
        elif name in asn_locations['domestic']:
            node.set("fillcolor", "#D4EBDD")
        else:
            node.set("fillcolor", "#CED1E8")
    return nodes
#
#
#    flat_structure = []
#    for route in routes:
#        for node in route:
#            if minimal == False:
#                asn = GEOIP_ASN.org_by_addr(node)
#            else:
#                asn = node[0]
#            if asn is None: continue
#            flat_structure.append(asn.split()[0])
#
#    region = {'flat_structure': None}
#    prlabel = None
#
#    for rlabel in region:
#        region[rlabel]=pydot.Cluster(rlabel,label=None, style="invis", rank="min")
#        region[rlabel].add_node(pydot.Node('node_'+rlabel, style="invis"))
#        if prlabel is not None: graph.add_edge(pydot.Edge('node_' + prlabel,'node_' + rlabel, style="invis", constraint = "false"))
#        graph.add_subgraph(region[rlabel])
#        prlabel = rlabel
#
#
#    for asn in cluster:
#        if asn in asn_locations['destination']:
#            cluster[asn].set("fillcolor", "#C9A9CD")
#            region['flat_structure'].add_subgraph(cluster[asn])
#        elif asn in asn_locations['start']:
#            cluster[asn].set("fillcolor", "#B1D7BF")
#            region['flat_structure'].add_subgraph(cluster[asn])
#        elif asn in asn_locations['domestic']:
#            cluster[asn].set("fillcolor", "#D4EBDD")
#            region['flat_structure'].add_subgraph(cluster[asn])
#        elif asn in flat_structure:
#            cluster[asn].set("fillcolor", "#CED1E8")
#            region['flat_structure'].add_subgraph(cluster[asn])
#        elif asn in gateways:
#            cluster[asn].set("fillcolor", "#B88F90")
#            region['gateway'].add_subgraph(cluster[asn])
#        elif asn in ends:
#            cluster[asn].set("fillcolor", "#7EA2A1")
#            region['end'].add_subgraph(cluster[asn])
#        elif asn in domestic:
#            cluster[asn].set("fillcolor", "#7EA2A1")
#            region['domestic'].add_subgraph(cluster[asn])
#        elif asn in international:
#            cluster[asn].set("fillcolor", "#B8AA8F")
#            region['international'].add_subgraph(cluster[asn])


def more_structured(graph, cluster, routes, target_country = "IR", minimal = False, asn_locations = None):
    global GEOIP_ASN, GEOIP_CC
    
    #    origins = [GEOIP_ASN.org_by_addr(route[0]).split()[0] for route in routes]
    #    ends = [GEOIP_ASN.org_by_addr(route[-1]).split()[0] for route in routes]
    #    gateways = ['AS12880', 'Private']
    #    domestic, international = [], []
    
    flat_structure = []
    for route in routes:
        for node in route:
            #            if node is 'q': continue
            if minimal == False:
                asn = GEOIP_ASN.org_by_addr(node)
            else:
                asn = node[0]
            if asn is None: continue
            flat_structure.append(asn.split()[0])
    #
    #            cc = GEOIP_CC.country_code_by_addr(node)
    #            if cc is target_country:
    #                domestic.append(asn.split()[0])
    #            # if transition international -> domestic: gw += [node]
    #            else:
    #                international.append(asn.split()[0])
    
    
    #    region = {'origin': None, 'international': None, 'gateway': None, 'domestic': None, 'end': None}
    region = {'flat_structure': None}
    prlabel = None
    
    for rlabel in region:
        region[rlabel]=pydot.Cluster(rlabel,label=None, style="invis", rank="min")
        region[rlabel].add_node(pydot.Node('node_'+rlabel, style="invis"))
        if prlabel is not None: graph.add_edge(pydot.Edge('node_' + prlabel,'node_' + rlabel, style="invis", constraint = "false"))
        graph.add_subgraph(region[rlabel])
        prlabel = rlabel
    
    print asn_locations
    for asn in cluster:
        if asn in asn_locations['destination']:
            cluster[asn].set("fillcolor", "#C9A9CD")
            region['flat_structure'].add_subgraph(cluster[asn])
        elif asn in asn_locations['start']:
            cluster[asn].set("fillcolor", "#B1D7BF")
            region['flat_structure'].add_subgraph(cluster[asn])
        elif asn in asn_locations['domestic']:
            cluster[asn].set("fillcolor", "#D4EBDD")
            region['flat_structure'].add_subgraph(cluster[asn])
        else:
            cluster[asn].set("fillcolor", "#CED1E8")
            region['flat_structure'].add_subgraph(cluster[asn])
#        elif asn in gateways:
#            cluster[asn].set("fillcolor", "#B88F90")
#            region['gateway'].add_subgraph(cluster[asn])
#        elif asn in ends:
#            cluster[asn].set("fillcolor", "#7EA2A1")
#            region['end'].add_subgraph(cluster[asn])
#        elif asn in domestic:
#            cluster[asn].set("fillcolor", "#7EA2A1")
#            region['domestic'].add_subgraph(cluster[asn])
#        elif asn in international:
#            cluster[asn].set("fillcolor", "#B8AA8F")
#            region['international'].add_subgraph(cluster[asn])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                                     prog='Scamper to Pydot',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('file_in', nargs='+', type=argparse.FileType('r'), default=None, help='Scamper Warts File to Parse')
    parser.add_argument('--file_out', default=None, help='Output file')

    output = parser.add_argument_group('Output Controls')
    output.add_argument('--maskip', metavar='ip', nargs='+', help='Mask IPs in Graph')
    output.add_argument('--maskhop', metavar='hop', type=int, nargs='+', help='Mask Hops in Graph')
    output.add_argument('--skiphop', metavar='hop', type=int, nargs='+', help='Skip Hops in Graph')
    output.add_argument('--format', metavar='format', choices=['dot','png','svg'], default='png', help='Output Format')
    output.add_argument('--responding', action='store_true', help='Skip non-responding nodes')
    output.add_argument('--minimal', action='store_true', help='Minimal Node Representation')
    output.add_argument('--sample', type=int, default=None, help='Random Sample')

    GEOIP_ASN	= pygeoip.GeoIP('common/GeoIPASNum.dat')
    GEOIP_CC      = pygeoip.GeoIP('common/GeoLiteCity.dat')

    COLORS		= ["#a6cee3", "#1f78b4","#b2df8a","#33a02c","#fb9a99","#e31a1c","#fdbf6f","#ff7f00","#cab2d6","#6a3d9a","#ffff99","#b15928"]
    COLOR_SE	= "#333333"
    logging.basicConfig(level=logging.WARN)

    args = parser.parse_args()

    main(args)