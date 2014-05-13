import itertools


# itertoos.permutations() instead of zip

Measurments = []
probs_list = [] #(string,description,cost)
Definitions_list = [] #(string, description, cost)

_target = '198.83.85.56'
_probs = """{"requested": 1,"type": "probes", "value": "16592" }"""


def cal_cost(IN):
    cost = 0
    if IN['is_oneoff'] == 'true':
        m = 2
    else:
        m = 1
    if IN['type'] == 'ping':
        return(m*IN['packets']*(int(IN['size']/1500)+1))
    elif IN['type'] == 'sslcert':
        return(m*10)
    elif IN['type'] == 'dns':
        if IN['protocol'] == 'TCP':
            return(m*20)
        elif IN['protocol'] == 'UDP':
            return(m*10)
    elif IN['type'] == 'traceroute':
        return(m*10*IN['packets']*(int(IN['size']/1500)+1))
    elif IN['type'] == 'sslcert':
        return(m*10)
    return cost

def traceroute(IN):
    return(""" { "target":"%s" , "description": "%s" ,"type": "%s"\
            ,"af": %s,"resolve_on_probe": %s ,"is_public": %s, "packets": %s ,\
            "protocol": %s , "paris": %s , "firsthop": %s , "interval": %s\
            ,"is_oneoff": %s }""" %(IN["target"],IN["description"],\
            IN["type"],IN["af"],IN["resolve_on_probe"],IN["is_public"],\
            str(IN["packets"]),IN["protocol"],str(IN["pairs"]),str(IN["firsthop"]),\
            str(IN["interval"]),IN["is_oneoff"])
            )

def ping(IN):
    return(""" { "target": "%s" , "description": "%s" ,"type": "%s"\
            ,"af": %s,"resolve_on_probe": %s ,"is_public": %s, "packets": %s\
            ,"size": %s, "is_oneoff": %s} """ %(IN["target"],IN["description"],\
            IN["type"],IN["af"],IN["resolve_on_probe"],IN["is_public"],str(IN["packets"]),\
            str(IN["size"]),IN["is_oneoff"])
            )
def dns(IN):
    return(""" { "target": "%s" , "description": "%s" ,"type": "%s"
            ,"af": %s,"resolve_on_probe": %s ,"is_public": %s, "do": %s
            ,"use_probe_resolver": %s, "use_NSID": %s, "query_class": %s\
            , "query_type": %s,"query_argument":,"":%s,"recursion_desired":%s\
            ,"protocol":"%s", "udp_payload_size":%s} """\
            %(IN["target"],IN["description"],IN["type"],IN["af"],IN["resolve_on_probe"]\
            ,IN["is_public"],str(IN["do"]),str(IN["use_probe_resolver"]),str(IN["use_NSID"])\
            ,str(IN['query_class']),str(IN['query_type']),str(IN['query_argument'])\
            ,str(IN['recursion_desired']),str(IN['protocol']),
            str(IN['udp_payload_size']))
            )

def ssl(IN):
    return(""" { "target": "%s" , "description": "%s" ,"type": "%s"\
            ,"af": %s,"resolve_on_probe": %s ,"is_public": %s, "packets":
            %s}"""%(IN["target"],IN["description"],\
            IN["type"],IN["af"],IN["resolve_on_probe"],IN["is_public"])
            )

def main():
#core
    _description = ''
    _type = ['ping','traceroute','dns', 'sslcert']
    _af = ['4', '6']
    _resolve_on_probe = ['true','false']
    _is_oneoff = 'true' 
    _is_public = 'false'

    ## Craft Ping ones:

    for (_a46,_res) in itertools.product(_af,_resolve_on_probe):

        IN = {}
        IN['target'] =_target
        IN['type'] = 'ping'
        IN['af'] = _a46
        IN['resolve_on_probe'] = _res
        IN['is_oneoff'] = _is_oneoff
        IN['is_public'] = _is_public
        _packets = [3,5,10]
        _size = [1,32,1024]
        for (s,p) in itertools.product(_size,_packets):
            IN['packets'] = p
            IN['size'] = s
            cost=cal_cost(IN)
            IN['description'] ='ping_'+IN['af']+'_'+_res+'_'+str(p)+'_'+str(s)+'_'+str(cost)
            _definitions = ping(IN)
            Main_str = """{"definitions": [%s],"probes": [%s]}"""%(_definitions,_probs)
            probs_list.append(Main_str)

    for (_a46,_res) in itertools.product(_af,_resolve_on_probe):

        IN = {}
        IN['target'] =_target
        IN['type'] = 'traceroute'
        IN['af'] = _a46
        IN['resolve_on_probe'] = _res
        IN['is_oneoff'] = _is_oneoff
        IN['is_public'] = _is_public

        # added by philipp
        _protocol = ['TCP','UDP']
        _dontfrag = ['true', 'false']
        _paris = ['1','15']
        _firsthop = ['1','64']
        _maxhops = ['64','128']
        _timeout = ['60','120']
        _packets = [3,5,10]
        # /added by philipp

        for (pro,dontf,pairs,h1,hM,tOut,s,p) in \
            itertools.product(_protocol,_dontfrag,_paris,_firsthop,_maxhops,_timeout,_size,_packets):
            IN['protocol'] = pro
            IN['dontfrag'] = dontf
            IN['pairs'] = pairs
            IN['firsthop'] = h1
            IN['maxhops'] = hM
            IN['timeout'] = tOut
            IN['size'] = s
            IN['packets'] = p
            cost = cal_cost(IN)
            IN['description'] = 'trace_' + \
                    IN['af'] + '_' + _res + '_' + \
                    IN['protocol'] + '_' + \
                    IN['dontfrag'] + '_' + \
                    IN['pairs'] + '_' + \
                    IN['firsthop'] + '_' + \
                    IN['maxhops'] + \
                    IN['timeout'] + '_' + \
                    str(IN['size']) + '_' + str(cost)

            _definitions = ping(IN)
            Main_str = """{"definitions": [%s],"probes": [%s]}"""%(_definitions,_probs)
            probs_list.append(Main_str)

    for (_a46,_res) in itertools.product(_af,_resolve_on_probe):

        IN = {}
        IN['target'] =_target
        IN['type'] = 'dns'
        IN['af'] = _a46
        IN['resolve_on_probe'] = _res
        IN['is_oneoff'] = _is_oneoff
        IN['is_public'] = _is_public
        _do = ['true', 'false']
        _use_probe_resolver = ['true', 'false']
        _use_NSID = ['true', 'false']
        _query_class = ['IN A', 'CHAOS']
        _query_type = []
        _query_argument = "www.google.com"
        _recursion_desired = ['true', 'false']
        _protocol = ['TCP','UDP']
        _udp_payload_size = ['false','true']

        for (d,p_r,NS,qc,qt,qa,rd,pro,ups) in \
            itertools.product(_do,_use_probe_resolver,_use_NSID\
            ,_query_class,_query_type,_query_argument\
            ,_recursion_desired,_protocol,_udp_payload_size):

            IN['do'] = d
            IN['use_probe_resolver']=p_r
            IN['use_NSID']=NS
            IN['query_class']=qc
            IN['query_type']=qt
            IN['query_argument']=qa
            IN['recursion_desired']=rd
            IN['protocol']=pro
            IN['udp_payload_size']=ups
            cost =cal_cost(IN)
            IN['description'] = 'dns' + '_' + \
                    IN['do'] + '_' + \
                    IN['use_probe_resolver'] + '_' + \
                    IN['use_NSID'] + '_' + \
                    IN['query_class'] + '_' + \
                    IN['query_type'] + '_' +  \
                    IN['query_argument'] + '_' + \
                    IN['recursion_desired'] + '_' + \
                    IN['protocol'] + '_' + \
                    IN['udp_payload_size'] + '_' + str(cost)


            _definitions = ping(IN)
            Main_str = """{"definitions": [%s],"probes": [%s]}"""%(_definitions,_probs)
            probs_list.append(Main_str)

    for (_a46,_res) in itertools.product(_af,_resolve_on_probe):

        IN = {}
        IN['target'] =_target
        IN['type'] = 'sslcert'
        IN['af'] = _a46
        IN['resolve_on_probe'] = _res
        IN['port'] = '443'
        # added by philipp
        IN['is_oneoff'] = 'true'
        IN['is_public'] = 'true'
        IN['size'] = 123
        IN['packets'] = [3, 5, 10]
        # /added by philipp

        cost=cal_cost(IN)
        IN['description'] = 'ssl_'+'_'+_a46+'_'+_res+'_'+str(cost)
        _definitions = ping(IN)
        Main_str = """{"definitions": [%s],"probes": [%s]}"""%(_definitions,_probs)
        probs_list.append(Main_str)

    with open('probs.txt','w') as outlog:
        for l in probs_list:
            outlog.write("%s\n" %l)
        outlog.close()


if __name__=='__main__':
        main()

    #probe (requested = 1 _type = ['area','prefix','asn','msm','probs'] _value = ['WW'])
