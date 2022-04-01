import json
from collections import defaultdict
from os import listdir
from os.path import isfile, join
from datetime import datetime
import pyasn
from OCSP_DNS_DJANGO.local import LOCAL
from OCSP_DNS_DJANGO.tools import AS2ISP

ttl_to_suffix_dict = {
    15: "",
}

# banned live_zeus_5_404 -> live_zeus_5_525 # live_zeus_5_499 porjonto allowed

as2isp = AS2ISP()

def get_org(asn):
    org = str(as2isp.getISP("20221212", asn)[0])
    cntry = str(as2isp.getISP("20221212", asn)[1])
    org.replace("\"", "")
    cntry.replace("\"", "")
    return org, cntry

def get_live_file_name(ttl):
    if ttl in ttl_to_suffix_dict:
        return "results"
    else:
        return "results_{}".format(ttl)

if LOCAL:
    asndb = pyasn.pyasn('../OCSP_DNS_DJANGO/ipsan_db.dat')
else:
    asndb = pyasn.pyasn('OCSP_DNS_DJANGO/ipsan_db.dat')

def get_leaf_files(path):
    import os
    list_of_files = []

    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


def get_asn(ip):
    return asndb.lookup(ip)[0]

incorrect_asn_set = set()

#file_iter = None
url_live = 'ttlexp.exp.net-measurement.net'
event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]
banned_exp_ids = ['live_node_30_8', 'live_node_30_1', 'live_node_30_68']
# resolver_mega = defaultdict(lambda: set())

phase_wise_resolver_correlation = defaultdict(lambda: defaultdict(lambda: 0))

###### Global:
http_response_dict = defaultdict(lambda: 0)
http_response_to_asn_set = defaultdict(lambda: set())
telemetry_count = {}

'''
Global:
req_id -> {Correct: 5, Incorrect: 20}
'''
final_dict = {}

'''
Global:
                        *List* Not Set*
resolver -> {Correct: [(req_id, ip_hash),(req_id, ip_hash)....], Incorrect: [(req_id, ip_hash),(req_id, ip_hash)....]}
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

first_hit_resolvers = []
all_resolvers_pool = []




'''
Global:
resolver_to_ips: resolver -> ips from req ids that hit those resolvers
                                *** not only considered resolvers from our method ***
'''

resolver_to_ips = defaultdict(lambda: set())

# TODO second phase pagne
'''
Global:
First phase
'''
req_id_to_bind_ips = defaultdict(lambda: set())

req_id_to_bind_ips_phase_2 = defaultdict(lambda: set())

'''
Global:
Per request id
'''
jaccard_index = []


global_asn_set = set()

if LOCAL:
    BASE_URL = '/Users/protick.bhowmick/PriyoRepos/OCSP_DNS_DJANGO/logs_final/'
else:
    BASE_URL = '/home/protick/ocsp_dns_django/ttldict/logs_final_v2/'


# OUTER

def initiate_per_ttl_global_sets():
    global incorrect_asn_set
    global http_response_dict
    global telemetry_count
    global final_dict
    global final_dict_elaborate
    global first_hit_resolvers

    global all_resolvers_pool
    global resolver_to_ips
    global req_id_to_bind_ips
    global req_id_to_bind_ips_phase_2
    global jaccard_index
    global global_asn_set
    global req_id_to_resolvers
    global req_id_to_client_ips
    global phase_wise_resolver_correlation
    global http_response_to_asn_set

    http_response_to_asn_set = defaultdict(lambda: set())
    phase_wise_resolver_correlation = defaultdict(lambda: defaultdict(lambda: 0))
    req_id_to_resolvers = defaultdict(lambda: set())
    req_id_to_client_ips = defaultdict(lambda: set())
    incorrect_asn_set = set()
    http_response_dict = defaultdict(lambda: 0)
    telemetry_count = {}
    final_dict = {}
    final_dict_elaborate = {}
    first_hit_resolvers = []
    all_resolvers_pool = []
    resolver_to_ips = defaultdict(lambda: set())
    req_id_to_bind_ips = defaultdict(lambda: set())
    req_id_to_bind_ips_phase_2 = defaultdict(lambda: set())
    jaccard_index = []
    global_asn_set = set()


def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def calc_correlation_matrix(phase1_resolvers, phase2_resolvers):
    for e1 in phase1_resolvers:
        for e2 in phase2_resolvers:
            phase_wise_resolver_correlation[e1][e2] += 1
            phase_wise_resolver_correlation[e2][e1] += 1


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
    # time = time[: time.rfind(".")]
    # 00:00:03.533
    datetime_object = datetime.strptime(time, '%d-%b-%Y-%H:%M:%S.%f')

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
                    if "req" not in d:
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
                except Exception as e:
                    print('parse bind apache logs ', e)

    return ans_dict


def segment(lst, d1, d2):
    ans = []
    for e in lst:
        if d1 < e['date'] < d2:
            ans.append(e)
    return ans


def track_bind_hits_per_req(info, req_to_bind_ip):
    for req in info:
        for e in info[req]:
            resolver_ip = e["resolver_ip"]
            req_to_bind_ip[req].add(resolver_ip)


def curate_time_segment(info, d1, d2):
    data = info["req"]
    ans = {}
    for req_id in data:
        lst = data[req_id]
        ans[req_id] = segment(lst, d1, d2)
    return ans

def save_telemetry(data):
    try:
        keys = ["phase_1_nxdomain", "phase_2_server2", "phase_2_nxdomain", "phase_1_server1"]
        nested_data = data["telemetry"]
        for key in keys:
            if key in nested_data:
                if key not in telemetry_count:
                    telemetry_count[key] = defaultdict(lambda: 0)
                telemetry_count[key][nested_data[key]] += 1
    except:
        pass


def preprocess_live_data(data):
    req_id_to_ip_hash = {}
    save_telemetry(data)
    d = data['dict_of_phases']
    ans = {}
    for k in d:
        try:
            js = d[k]
            req_url = js['req_url'][7:]
            req_id = str(req_url.split(".")[0])
            phase_1 = js['host-phase-1']
            phase_2 = js['host-phase-2']

            http_response_dict[js["1-response"]] += 1
            http_response_dict[js["2-response"]] += 1



            asn = js['asn']

            http_response_to_asn_set[js["1-response"]].add(asn)
            http_response_to_asn_set[js["2-response"]].add(asn)

            global_asn_set.add(asn)
            ans[req_id] = (phase_1, phase_2, js['asn'])
            req_id_to_ip_hash[req_id] = js['ip_hash']
        except Exception as e:
            print('preprocess_live_data ' , e)
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
    bind_dir = BASE_URL + 'bind/bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    apache_logs_phase_1_dir = BASE_URL + 'apache_1/apache2/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in listdir(apache_logs_phase_1_dir) if
                           isfile(join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = BASE_URL + 'apache_2/apache2/'
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


def parse_logs_ttl(exp_id, bind_info, apache_info_one, apache_info_two, ttl):

    # TODO WATCH
    lists_in_hand = [apache_info_one, apache_info_two, bind_info]

    for l in lists_in_hand:
        for k in event_strings:
            if k in l:
                l[k].sort(key=lambda x: x['date'])
        for k in l['req']:
            l['req'][k].sort(key=lambda x: x['date'])

        # TIME
        for k in bind_info['req']:
            if len(bind_info['req'][k]) > 0:
                first_item_resolver_ip = bind_info['req'][k][0]['resolver_ip']
                first_hit_resolvers.append(first_item_resolver_ip)
                for ele in bind_info['req'][k]:
                    ip_resolver = ele['resolver_ip']
                    all_resolvers_pool.append(ip_resolver)

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

    track_bind_hits_per_req(bind_info_curated_first, req_to_bind_ip=req_id_to_bind_ips)
    track_bind_hits_per_req(bind_info_curated_second, req_to_bind_ip=req_id_to_bind_ips_phase_2)

    # 'live_zeus_15_1_10'
    segments = exp_id.split("_")
    exp_iteration = int(segments[-2])

    live_file_seg = get_live_file_name(ttl)
    live_log = open(BASE_URL + "live/{}/{}/{}-out.json".format(live_file_seg, exp_iteration, exp_id))

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

        calc_correlation_matrix(phase1_resolvers, phase2_resolvers)

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

        calc_correlation_matrix(phase1_resolvers, phase2_resolvers)

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
    live_jsons_dir = BASE_URL + 'live/node_code/'.format(file_iter)
    run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
                 and '.json' in f and 'live_node' in f]

    asn_set = set()
    for e in run_jsons:
        live_log = open(BASE_URL + "live/node_code/{}".format(file_iter, e))
        live_data, req_id_to_ip_hash = preprocess_live_data(json.load(live_log))
        for key in live_data:
            asn_set.add(live_data[key][2])

    with open("ttl_exp_asn_list.json", "w") as ouf:
        json.dump(list(asn_set), fp=ouf)

# TODO _.live_node_30_185.31313.ttlexp.exp.net-measurement.net
# TODO query steps
# global: resolver_ip_against -> ip1, ip2, ip3


def parc():
    get_leaf_files(BASE_URL + 'live/results')


def table_maker_preprocess(d, parent_path):
    ans = defaultdict(lambda: [0, set()])
    c_ans = defaultdict(lambda: [0, set()])
    final_dict = d["data_elaborate"]

    cn = {}
    # cnt, tot = 0, 0
    for key in final_dict:
        correct_set = set()
        incorrect_set = set()
        for e in final_dict[key]["ic"]:
            incorrect_set.add(e[1])
        for e in final_dict[key]["c"]:
            correct_set.add(e[1])
        total = len(correct_set) + len(incorrect_set)
        total_set = correct_set.union(incorrect_set)
        if total < 5:
            continue
        ratio = len(incorrect_set) / total
        if ratio >= .95:
            asn = get_asn(key)
            org, cntry = get_org(asn)
            ans[org][0] += 1
            ans[org][1].update(total_set)
            cn[org] = cntry
        elif ratio <= .05:
            asn = get_asn(key)
            org, cntry = get_org(asn)
            c_ans[org][0] += 1
            c_ans[org][1].update(total_set)
            cn[org] = cntry

    ans_lst = []
    c_ans_lst = []
    l = 0
    for key in ans:
        l += ans[key][0]
        correct_count = 0
        if key in c_ans:
            correct_count = c_ans[key][0]
        ans_lst.append((ans[key][0], len(ans[key][1]), key, cn[key], correct_count))
                        # resolver count, exit node count, isp, cntry, opposite

    for key in c_ans:
        l += c_ans[key][0]
        in_correct_count = 0
        if key in ans:
            in_correct_count = ans[key][0]
        c_ans_lst.append((c_ans[key][0],  len(c_ans[key][1]), key, cn[key], in_correct_count))

    k = {}
    k['ic_ans_lst'] = ans_lst
    k['c_ans_lst'] = c_ans_lst
    with open(parent_path + "table_data.json", "w") as ouf:
        json.dump(k, fp=ouf)


def local_public_analyzer(data, parent_path):

    d = data
    resolver_to_asns = d['resolver_to_asns']
    resolver_to_asn_own = d['resolver_to_asn_own']
    resolver_to_org_country = {}
    is_resolver_public = {}
    local_count, public_count = 0, 0
    for resolver in resolver_to_asns:
        ip_list = resolver_to_asns[resolver]
        org_set = set()
        cntry_set = set()

        resolver_asn = resolver_to_asn_own[resolver]
        res_org, cntry = get_org(resolver_asn)
        resolver_to_org_country[resolver] = (res_org, cntry)

        for ip_tuple in ip_list:
            asn = ip_tuple[1]
            org, cntry = get_org(asn)
            org_set.add(org)
            cntry_set.add(cntry)

        if len(cntry_set) > 1:
            is_resolver_public[resolver] = True
            public_count += 1
        elif len(org_set) == 1 and list(org_set)[0] == res_org:
            local_count += 1
            is_resolver_public[resolver] = False

    # print("Total ", len(list(resolver_to_asns.keys())))
    # print("Public ", public_count)
    # print("Local ", local_count)

    with open(parent_path + "resolver_public_local_dict.json", "w") as ouf:
        json.dump(is_resolver_public, fp=ouf)

    with open(parent_path + "resolver_to_org_country.json", "w") as ouf:
        json.dump(resolver_to_org_country, fp=ouf)


def is_allowed(element, lst):
    for e in lst:
        if element == e:
            return True
    return False


def master_calc(ttl_list):
    live_jsons_dir = BASE_URL + 'live/results'

    leaf_files_unfiltered = get_leaf_files(BASE_URL + 'live/')
    leaf_files_filtered = [e.split("/")[-1] for e in leaf_files_unfiltered]
    leaf_files_filtered = [e for e in leaf_files_filtered if ".json" in e]

    # run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
    #              and '.json' in f and 'live_node' in f]

    exp_id_list = []
    pp = []
    for element in leaf_files_filtered:
        exp_id_list.append(element[: - len("-out.json")])

    ttl_to_exp_id_list = defaultdict(lambda: list())

    exp_id_list_temp = []
    for e in exp_id_list:
        segments = e.split("_")
        ttl_temp = int(segments[-3])
        if not is_allowed(ttl_temp, ttl_list):
            continue
        ttl_to_exp_id_list[ttl_temp].append(e)
        exp_id_list_temp.append(e)

    exp_id_list = exp_id_list_temp

    # 'live_zeus_15_1_10'
    bind_info_global, apache_info_one_global, apache_info_two_global = parse_logs_together(allowed_exp_ids=exp_id_list)
    send_telegram_msg("Done with parsing bind/apache logs")

    # banned live_zeus_5_404 -> live_zeus_5_525 # live_zeus_5_499 porjonto allowed
    banned_list = []
    # live_zeus_5_403_1-out.json
    for i in range(490, 526):
        for j in range(1, 7):
            banned_list.append("live_zeus_5_{}_{}".format(i, j))







    for ttl in ttl_to_exp_id_list:
        initiate_per_ttl_global_sets()
        exp_id_nested = ttl_to_exp_id_list[ttl]
        for exp_id in exp_id_nested:
            try:
                if exp_id in banned_list:
                    continue
                cs, ics = parse_logs_ttl(exp_id=exp_id,
                                         bind_info=bind_info_global[exp_id],
                                         apache_info_one=apache_info_one_global[exp_id],
                                         apache_info_two=apache_info_two_global[exp_id],
                                         ttl=ttl)
            except Exception as e:
                pp.append('master_calc {} {}'.format(e, exp_id))
                print('master_calc ', e, exp_id)

        send_telegram_msg("Done with parsing TTL init {}".format(ttl))

        from pathlib import Path
        parent_path = 'ttl_result/{}/'.format(ttl)
        Path(parent_path).mkdir(parents=True, exist_ok=True)
        # print("Total resolvers {}".format(len(list(final_dict.keys()))))
        # print("Total exit-nodes covered {}".format(len(list(req_id_to_resolvers.keys()))))

        data_final = {}
        data_final["Total_resolvers"] = len(list(final_dict.keys()))
        # data_final["Total_ex_nodes"] = len(list(req_id_to_resolvers.keys()))
        data_final["data"] = final_dict
        data_final["data_elaborate"] = final_dict_elaborate

        with open(parent_path + "final_data.json", "w") as ouf:
            json.dump(data_final, fp=ouf)

        try:
            table_maker_preprocess(d=data_final, parent_path=parent_path)
        except:
            pass

        with open(parent_path + "incorrect_ans_set.json", "w") as ouf:
            json.dump(list(incorrect_asn_set), fp=ouf)

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

        first_hit_set = set(first_hit_resolvers)
        for resolver in first_hit_set:
            if resolver not in resolver_to_asn_own:
                resolver_to_asn_own[resolver] = get_asn(resolver)

        resolver_asn_bonanza = {
            "resolver_to_asns": resolver_to_asns,
            "resolver_to_asn_own": resolver_to_asn_own
        }

        # TODO CHANGE of File name
        with open(parent_path + "final_resolver_to_asn.json", "w") as ouf:
            json.dump(resolver_asn_bonanza, fp=ouf)

        try:
            local_public_analyzer(resolver_asn_bonanza, parent_path)
        except Exception as e:
            pass

        '''
        Global:
        First phase
        '''
        req_id_to_bind_ips_cp = {}
        for key in req_id_to_bind_ips:
            req_id_to_bind_ips_cp[key] = list(req_id_to_bind_ips[key])

        req_id_to_bind_ips_cp_2 = {}
        for key in req_id_to_bind_ips_phase_2:
            req_id_to_bind_ips_cp_2[key] = list(req_id_to_bind_ips_phase_2[key])

        with open(parent_path + "req_id_to_bind_ips.json", "w") as ouf:
            json.dump(req_id_to_bind_ips_cp, fp=ouf)

        with open(parent_path + "req_id_to_bind_ips_phase_2.json", "w") as ouf:
            json.dump(req_id_to_bind_ips_cp_2, fp=ouf)

        with open(parent_path + "jaccard_index.json", "w") as ouf:
            json.dump(jaccard_index, fp=ouf)

        with open(parent_path + "correlation_resolvers.json", "w") as ouf:
            json.dump(phase_wise_resolver_correlation, fp=ouf)

        with open(parent_path + "first_hit_resolvers.json", "w") as ouf:
            json.dump(first_hit_resolvers, fp=ouf)

        # all_resolvers_pool
        ip_to_count = defaultdict(lambda: 0)
        for e in all_resolvers_pool:
            ip_to_count[e] += 1
        ans_x = []
        for key in ip_to_count:
            ans_x.append((key, ip_to_count[key]))
        ans_x.sort(key=lambda x: -x[1])

        with open(parent_path + "all_resolvers_pool.json", "w") as ouf:
            json.dump(ans_x, fp=ouf)

        with open(parent_path + "global_asn_list.json", "w") as ouf:
            json.dump(list(global_asn_set), fp=ouf)

        with open(parent_path + "telemetry_count.json", "w") as ouf:
            json.dump(telemetry_count, fp=ouf)

        with open(parent_path + "http_response_dict.json", "w") as ouf:
            json.dump(http_response_dict, fp=ouf)

        try:
            temp_dict = {}
            for key in http_response_to_asn_set:
                temp_dict[key] = list(http_response_to_asn_set[key])
            with open(parent_path + "http_response_to_asn_list.json", "w") as ouf:
                json.dump(temp_dict, fp=ouf)
        except:
            pass

        send_telegram_msg("Done with parsing TTL final {}".format(ttl))


def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])

