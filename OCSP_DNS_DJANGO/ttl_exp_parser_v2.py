import json
from collections import defaultdict
from os import listdir
from os.path import isfile, join
from datetime import datetime
import pyasn

asndb = pyasn.pyasn('OCSP_DNS_DJANGO/ipsan_db.dat')

def get_asn(ip):
    return asndb.lookup(ip)[0]

incorrect_asn_set = set()

#file_iter = None
url_live = 'ttlexp.exp.net-measurement.net'
event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]
banned_exp_ids = ['live_node_30_8', 'live_node_30_1', 'live_node_30_68']
# resolver_mega = defaultdict(lambda: set())

'''
Global:
req_id -> {Correct: 5, Incorrect: 20}
'''
final_dict = {}

'''
Global:
                        *List* Not Set*
req_id -> {Correct: [(req_id, ip_hash),(req_id, ip_hash)....], Incorrect: [(req_id, ip_hash),(req_id, ip_hash)....]}
'''
final_dict_elaborate = {}

'''
Global:
req_id_to_resolvers: both phases!
'''
req_id_to_resolvers = defaultdict(lambda: set())


'''
Global:
req_id_to_client_ips: both phases!
'''
req_id_to_client_ips = defaultdict(lambda: set())


'''
Global:
resolver_to_ips: resolver -> ips from req ids that hit those resolvers
                                *** not only considered resolvers from our method ***
'''
resolver_to_ips = defaultdict(lambda: set())

'''
Global:
First phase
'''
req_id_to_bind_ips = defaultdict(lambda: set())

'''
Global:
Per request id
'''
jaccard_index = []


def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def does_exp_id_match(line, exp_id_list):
    for exp_id in exp_id_list:
        string_to_look_for = exp_id + "."
        if string_to_look_for in line:
            return True, exp_id
    return False, None


def parse_bind_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[0] + "-" + segments[1]
    resolver_ip = segments[5]
    resolver_ip = resolver_ip[: resolver_ip.rfind("#")]

    url = segments[8]
    time = time[: time.rfind(".")]
    datetime_object = datetime.strptime(time, '%d-%b-%Y-%H:%M:%S')

    meta = {}
    meta["date"] = datetime_object
    meta["url"] = url
    meta["resolver_ip"] = resolver_ip

    return meta


def parse_apache_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[4]
    client_ip = segments[0]
    url = segments[-1]
    time = time[1:len(time) - 1]
    time = time.split()[0]
    # 24-Feb-2022 00:00:58.505 bind
    # 24/Feb/2022:00:49:45 apache
    # time = time[: time.rfind(".")]
    datetime_object = datetime.strptime(time, '%d/%b/%Y:%H:%M:%S')

    meta = {}
    meta["date"] = datetime_object
    meta["url"] = url
    meta["client_ip"] = client_ip

    return meta


def parse_bind_apache_logs(exp_id_list, files, is_bind=True):
    ans_dict = defaultdict(lambda: dict())

    for file in files:
        with open(file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue

                    is_exp_id_present, exp_id = does_exp_id_match(line, exp_id_list)
                    if not is_exp_id_present:
                        continue
                    d = ans_dict[exp_id]
                    d["req"] = {}

                    if is_bind:
                        if line.startswith("client"):
                            continue

                    if is_bind:
                        meta = parse_bind_line_and_build_meta(line=line)
                    else:
                        meta = parse_apache_line_and_build_meta(line=line)

                    url = meta["url"]
                    is_event = is_event_log(url)

                    if is_event:
                        if is_event not in d:
                            d[is_event] = []
                        d[is_event].append(meta)
                    else:
                        identifier = str(url.split(".")[0])
                        if identifier not in d["req"]:
                            d["req"][identifier] = list()
                        d["req"][identifier].append(meta)
                        if is_bind:
                            req_id_to_resolvers[identifier].add(meta["resolver_ip"])
                        else:
                            req_id_to_client_ips[identifier].add(meta["client_ip"])
                except:
                    pass

    return ans_dict

def segment(lst, d1, d2):
    ans = []
    for e in lst:
        if d1 < e['date'] < d2:
            ans.append(e)
    return ans


def track_bind_hits_per_req(info):
    for req in info:
        for e in info[req]:
            resolver_ip = e["resolver_ip"]
            req_id_to_bind_ips[req].add(resolver_ip)


def curate_time_segment(info, d1, d2):
    data = info["req"]
    ans = {}
    for req_id in data:
        lst = data[req_id]
        ans[req_id] = segment(lst, d1, d2)
    return ans


def preprocess_live_data(data):
    req_id_to_ip_hash = {}

    d = data['dict_of_phases']
    ans = {}
    for k in d:
        try:
            js = d[k]
            req_url = js['req_url'][7:]
            req_id = str(req_url.split(".")[0])
            phase_1 = js['host-phase-1']
            phase_2 = js['host-phase-2']
            ans[req_id] = (phase_1, phase_2, js['asn'])
            req_id_to_ip_hash[req_id] = js['ip_hash']
        except Exception as e:
            pass
    return ans, req_id_to_ip_hash


def get_non_lum_resolver_ips(bind_info, req_id, lum_resolvers):
    lst = bind_info[req_id]  # ['resolver_ip']
    resolvers = set()
    for e in lst:
        ip = e['resolver_ip']
        if ip not in lum_resolvers:
            resolvers.add(ip)
    return resolvers


def parse_logs_together(allowed_exp_ids):
    bind_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/bind/bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    apache_logs_phase_1_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/apache_1/apache2/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in listdir(apache_logs_phase_1_dir) if
                           isfile(join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/apache_2/apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in listdir(apache_logs_phase_2_dir) if
                           isfile(join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files, is_bind=True)
    apache_info_one_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_1, is_bind=False)
    apache_info_two_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_2, is_bind=False)

    return bind_info_global, apache_info_one_global, apache_info_two_global


def log_considered_resolvers(considered_resolvers, req_id, ip_hash, is_correct_set=True):
    for key in considered_resolvers:
        if key not in final_dict:
            final_dict[key] = {"c": 0, "ic": 0}
        if key not in final_dict_elaborate:
            final_dict_elaborate[key] = {"c": list(), "ic": list()}

        if is_correct_set:
            final_dict[key]["c"] = 1 + final_dict[key]["c"]
            final_dict_elaborate[key]["c"].append((req_id, ip_hash))
        else:
            final_dict[key]["ic"] = 1 + final_dict[key]["ic"]
            final_dict_elaborate[key]["ic"].append((req_id, ip_hash))


def parse_logs_ttl(exp_id, bind_info, apache_info_one, apache_info_two):

    # TODO WATCH
    lists_in_hand = [apache_info_one, apache_info_two, bind_info]

    for l in lists_in_hand:
        for k in event_strings:
            if k in l:
                l[k].sort(key=lambda x: x['date'])
        for k in l['req']:
            l['req'][k].sort(key=lambda x: x['date'])

    # apache_phase_1_start = apache_info_one["phase1-start"][0]['date']
    # apache_phase_1_divider = apache_info_one["phase1-end"][0]['date']
    # apache_phase_2_start = apache_info_two["sleep-end"][0]['date']
    # apache_phase_2_end = apache_info_two["phase2-end"][0]['date']

    bind_phase_1_start = bind_info["phase1-start"][0]['date']
    bind_phase_1_end = bind_info["phase1-end"][0]['date']
    bind_phase_2_start = bind_info["sleep-end"][0]['date']
    bind_phase_2_end = bind_info["phase2-end"][0]['date']

    bind_info_curated_first = curate_time_segment(bind_info, bind_phase_1_start, bind_phase_1_end)
    bind_info_curated_second = curate_time_segment(bind_info, bind_phase_2_start, bind_phase_2_end)
    # apache_info_one_phase_1 = curate_time_segment(apache_info_one, apache_phase_1_start, apache_phase_1_divider)
    # apache_info_one_phase_2 = curate_time_segment(apache_info_one, apache_phase_2_start, apache_phase_2_end)
    # apache_info_two_curated_phase_2 = curate_time_segment(apache_info_two, apache_phase_2_start, apache_phase_2_end)

    track_bind_hits_per_req(bind_info_curated_first)

    live_log = open("/home/protick/ocsp_dns_django/ttldict/logs_final/live/node_code/{}-out.json".format(exp_id))

    # live_data: req_id -> (phase_1_webserver, phase_2_webserver, asn)
    # req_id_to_ip_hash: req_id -> ip_hash'
    live_data, req_id_to_ip_hash = preprocess_live_data(json.load(live_log))

    correct_set = set()
    incorrect_set = set()

    for req_id in live_data:
        if live_data[req_id][0] == 1 and live_data[req_id][1] == 1:
            incorrect_set.add(req_id)
            incorrect_asn_set.add(live_data[req_id][2])
        elif live_data[req_id][0] == 1 and live_data[req_id][1] == 2:
            correct_set.add(req_id)

    for req_id in correct_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, [])
        phase2_resolvers = get_non_lum_resolver_ips(bind_info_curated_second, req_id, [])

        considered_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        all_resolvers = phase1_resolvers.union(phase2_resolvers)

        if len(all_resolvers) > 0:
            jaccard_index.append(len(considered_resolvers) / len(all_resolvers))

        log_considered_resolvers(considered_resolvers=considered_resolvers,
                                 req_id=req_id,
                                 ip_hash=req_id_to_ip_hash[req_id],
                                 is_correct_set=True)


    for req_id in incorrect_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, [])
        phase2_resolvers = get_non_lum_resolver_ips(bind_info_curated_second, req_id, [])

        considered_resolvers = phase1_resolvers.difference(phase2_resolvers)

        common_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        all_resolvers = phase1_resolvers.union(phase2_resolvers)
        if len(all_resolvers) > 0:
            jaccard_index.append(len(common_resolvers) / len(all_resolvers))

        log_considered_resolvers(considered_resolvers=considered_resolvers,
                                 req_id=req_id,
                                 ip_hash=req_id_to_ip_hash[req_id],
                                 is_correct_set=False)

    return correct_set, incorrect_set


def get_all_asns(file_iter):
    live_jsons_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/live/node_code/'.format(file_iter)
    run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
                 and '.json' in f and 'live_node' in f]

    asn_set = set()
    for e in run_jsons:
        live_log = open("/home/protick/ocsp_dns_django/ttldict/logs_final/live/node_code/{}".format(file_iter, e))
        live_data, req_id_to_ip_hash = preprocess_live_data(json.load(live_log))
        for key in live_data:
            asn_set.add(live_data[key][2])

    with open("ttl_exp_asn_list.json", "w") as ouf:
        json.dump(list(asn_set), fp=ouf)

# TODO _.live_node_30_185.31313.ttlexp.exp.net-measurement.net
# TODO query steps
# global: resolver_ip_against -> ip1, ip2, ip3
def master_calc(file_it):
    file_iter = file_it
    live_jsons_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/live/node_code'
    run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
                 and '.json' in f and 'live_node' in f]

    exp_id_list = []
    for element in run_jsons:
        exp_id_list.append(element[: - len("-out.json")])

    bind_info_global, apache_info_one_global, apache_info_two_global = parse_logs_together(allowed_exp_ids=exp_id_list)
    send_telegram_msg("Done with parsing bind/apache logs")
    for exp_id in exp_id_list:
        try:
            cs, ics = parse_logs_ttl(exp_id=exp_id,
                                     bind_info=bind_info_global[exp_id],
                                     apache_info_one=apache_info_one_global[exp_id],
                                     apache_info_two=apache_info_two_global[exp_id])
            send_telegram_msg("Done with parsing {}".format(exp_id))
        except Exception as e:
            print(e)


    print("Total resolvers {}".format(len(list(final_dict.keys()))))
    # print("Total exit-nodes covered {}".format(len(list(req_id_to_resolvers.keys()))))

    data_final = {}
    data_final["Total_resolvers"] = len(list(final_dict.keys()))
    # data_final["Total_ex_nodes"] = len(list(req_id_to_resolvers.keys()))
    data_final["data"] = final_dict
    data_final["data_elaborate"] = final_dict_elaborate

    with open("final_data.json", "w") as ouf:
        json.dump(data_final, fp=ouf)

    with open("incorrect_ans_set.json", "w") as ouf:
        json.dump(list(incorrect_asn_set), fp=ouf)

    send_telegram_msg("Done with parsing phase 1")

    distinct_ips = set()

    for req_id in req_id_to_resolvers:
        resolvers = req_id_to_resolvers[req_id]
        ips = req_id_to_client_ips[req_id]
        distinct_ips.update(ips)
        for resolver in resolvers:
            resolver_to_ips[resolver].update(ips)

    ip_to_asn_dict = dict()
    for ip in distinct_ips:
        ip_to_asn_dict[ip] = get_asn(ip)

    '''
    Global
    Considers every resolver to req id mapping, not only considered resolvers
    '''
    resolver_to_asn_own = {}
    resolver_to_asns = defaultdict(lambda: list())
    for resolver in resolver_to_ips:
        resolver_to_asn_own[resolver] = get_asn(resolver)
        for ip in resolver_to_ips[resolver]:
            resolver_to_asns[resolver].append((ip, ip_to_asn_dict[ip]))

    resolver_asn_bonanza = {
        "resolver_to_asns": resolver_to_asns,
        "resolver_to_asn_own": resolver_to_asn_own
    }

    # TODO CHANGE of File name
    with open("final_resolver_to_asn.json", "w") as ouf:
        json.dump(resolver_asn_bonanza, fp=ouf)

    '''
    Global:
    First phase
    '''
    req_id_to_bind_ips_cp = {}
    for key in req_id_to_bind_ips:
        req_id_to_bind_ips_cp[key] = list(req_id_to_bind_ips[key])
    with open("req_id_to_bind_ips.json", "w") as ouf:
        json.dump(req_id_to_bind_ips_cp, fp=ouf)

    with open("jaccard_index.json", "w") as ouf:
        json.dump(jaccard_index, fp=ouf)

    send_telegram_msg("Done with parsing phase 2")


def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])