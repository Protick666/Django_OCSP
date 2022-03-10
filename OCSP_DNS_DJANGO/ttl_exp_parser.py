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

#req_id_to_resolvers = defaultdict(lambda: [set(), set()])
final_dict = {}
final_dict_elaborate = {}

req_id_to_resolvers = defaultdict(lambda: set())
req_id_to_client_ips = defaultdict(lambda: set())
resolver_to_ips = defaultdict(lambda: set())
req_id_to_bind_ips = defaultdict(lambda: set())

jaccard_index = []



def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def parse_bind_logs(exp_id, bind_files, resolver_pool):
    d = {}
    d["req"] = {}
    for bind_file in bind_files:
        with open(bind_file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue
                    if exp_id not in line:
                        continue
                    if line.startswith("client"):
                        continue

                    l = line.strip()
                    segments = l.split(" ")
                    time = segments[0] + "-" + segments[1]
                    resolver_ip = segments[5]
                    resolver_ip = resolver_ip[: resolver_ip.rfind("#")]

                    resolver_pool[resolver_ip] = resolver_pool[resolver_ip] + 1

                    url = segments[8]
                    time = time[: time.rfind(".")]
                    datetime_object = datetime.strptime(time, '%d-%b-%Y-%H:%M:%S')

                    meta = {}
                    meta["date"] = datetime_object
                    meta["url"] = url
                    meta["resolver_ip"] = resolver_ip
                    # "a94b66c4-a627-4e95-addf-bb1df40e98fa-1645660853.live1.ttlexp.exp.net-measurement.net"
                    # "fb6a8dbc-a96f-4dc8-9937-ae5705c28f3b.live1.1.phase1-end.ttlexp.exp.net-measurement.net"

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
                        req_id_to_resolvers[identifier].add(meta["resolver_ip"])
                        #resolver_mega[resolver_ip].add(identifier)
                except:
                    pass

    return d


def parse_apace_logs(exp_id, apache_files):
    d = {}
    d["req"] = {}
    for file in apache_files:
        with open(file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue
                    if exp_id not in line:
                        continue

                    l = line.strip()
                    segments = l.split(" ")
                    time = segments[4]
                    client_ip = segments[0]
                    url = segments[-1]
                    time = time[1:len(time) - 1]
                    time = time.split()[0]
                    # 24-Feb-2022 00:00:58.505 bind
                    # 24/Feb/2022:00:49:45 apache
                    #time = time[: time.rfind(".")]
                    datetime_object = datetime.strptime(time, '%d/%b/%Y:%H:%M:%S')

                    meta = {}
                    meta["date"] = datetime_object
                    meta["url"] = url
                    meta["client_ip"] = client_ip

                    is_event = is_event_log(url)

                    if is_event:
                        if is_event not in d:
                            d[is_event] = []
                        d[is_event].append(meta)
                    else:
                        identifier = str(url.split(".")[0])
                        if identifier not in d["req"]:
                            d["req"][identifier] = []
                        d["req"][identifier].append(meta)
                        req_id_to_client_ips[identifier].add(meta["client_ip"])
                except:
                    pass
    return d


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
            #req_id = js['req_id']
            phase_1 = js['host-phase-1']
            phase_2 = js['host-phase-2']
            # ans[req_id] = (phase_1, phase_2)
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


def parse_logs_ttl(exp_id):
    print("Doing {}".format(exp_id))
    resolver_pool = defaultdict(lambda: 0)
    lum_resolvers = []

    # TODO WATCH
    bind_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/bind/bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    apache_logs_phase_1_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/apache_1/apache2/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in listdir(apache_logs_phase_1_dir) if
                           isfile(join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/apache_2/apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in listdir(apache_logs_phase_2_dir) if
                           isfile(join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info = parse_bind_logs(exp_id=exp_id, bind_files=bind_files, resolver_pool=resolver_pool)
    apache_info_one = parse_apace_logs(exp_id=exp_id, apache_files=apache_logs_phase_1)
    apache_info_two = parse_apace_logs(exp_id=exp_id, apache_files=apache_logs_phase_2)

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
    live_data, req_id_to_ip_hash = preprocess_live_data(json.load(live_log))

    correct_set = set()
    incorrect_set = set()

    # correct_resolvers = set()
    # incorrect_resolvers = set()
    # common_resolvers = set()

    for req_id in live_data:
        if live_data[req_id][0] == 1 and live_data[req_id][1] == 1:
            incorrect_set.add(req_id)
            incorrect_asn_set.add(live_data[req_id][2])
        elif live_data[req_id][0] == 1 and live_data[req_id][1] == 2:
            correct_set.add(req_id)

    # print("Total reqs {}".format(len(list(live_data.keys()))))
    # print("Total correct reqs {}".format(len(correct_set)))
    # print("Total incorrect reqs {}".format(len(incorrect_set)))

    #req_id_to_phase_resolvers = defaultdict(lambda: [set(), set()])

    # for req_id in req_id_to_resolvers:
    #     k = None
    #     if req_id in correct_set:
    #         k = "c"
    #         resolvers = req_id_to_resolvers[req_id][0].intersection(req_id_to_resolvers[req_id][1])
    #         # final_dict[key]["c"] = 1 + final_dict[key]["c"]
    #     elif req_id in incorrect_set:
    #         k = "ic"
    #         resolvers = req_id_to_resolvers[req_id][0].difference(req_id_to_resolvers[req_id][1])
    #         # final_dict[key]["ic"] = 1 + final_dict[key]["ic"]
    #
    #     for key in resolvers:
    #         if key not in final_dict:
    #             final_dict[key] = {"c": 0, "ic": 0}
    #         final_dict[key][k] = 1 + final_dict[key][k]

    for req_id in correct_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, lum_resolvers)
        phase2_resolvers = get_non_lum_resolver_ips(bind_info_curated_second, req_id, lum_resolvers)

        considered_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        all_resolvers = phase1_resolvers.union(phase2_resolvers)
        jaccard_index.append(len(considered_resolvers) / len(all_resolvers))
        for key in considered_resolvers:
            if key not in final_dict:
                final_dict[key] = {"c": 0, "ic": 0}
            final_dict[key]["c"] = 1 + final_dict[key]["c"]

            if key not in final_dict_elaborate:
                final_dict_elaborate[key] = {"c": list(), "ic": list()}
            final_dict_elaborate[key]["c"].append((req_id, req_id_to_ip_hash[req_id]))

        # req_id_to_resolvers[req_id][0].update(phase1_resolvers)
        # req_id_to_resolvers[req_id][1].update(phase2_resolvers)
        #
        # correct_resolvers.update(phase1_resolvers.intersection(phase2_resolvers))

    for req_id in incorrect_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, lum_resolvers)
        phase2_resolvers = get_non_lum_resolver_ips(bind_info_curated_second, req_id, lum_resolvers)

        considered_resolvers = phase1_resolvers.difference(phase2_resolvers)

        common_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        all_resolvers = phase1_resolvers.union(phase2_resolvers)
        jaccard_index.append(len(common_resolvers) / len(all_resolvers))

        # TODO watch distinct
        for key in considered_resolvers:
            if key not in final_dict:
                final_dict[key] = {"c": 0, "ic": 0}
            final_dict[key]["ic"] = 1 + final_dict[key]["ic"]

            if key not in final_dict_elaborate:
                final_dict_elaborate[key] = {"c": list(), "ic": list()}
            final_dict_elaborate[key]["ic"].append((req_id, req_id_to_ip_hash[req_id]))

        # req_id_to_resolvers[req_id][0].update(phase1_resolvers)
        # req_id_to_resolvers[req_id][1].update(phase2_resolvers)
        #
        # queries_from_second_phase = get_non_lum_resolver_ips(bind_info_curated_second, req_id, lum_resolvers)
        # common_resolvers.update(phase1_resolvers.intersection(queries_from_second_phase))
        #
        # phase1_resolvers_incorrect = phase1_resolvers
        # incorrect_resolvers.update(phase1_resolvers_incorrect)

    # incorrect_resolvers = incorrect_resolvers.difference(correct_resolvers)
    # incorrect_resolvers = incorrect_resolvers.difference(common_resolvers)

    # all_resolvers = set()
    #
    # for key in resolver_pool:
    #     all_resolvers.add(key)

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



# global: resolver_ip_against -> ip1, ip2, ip3
def master_calc(file_it):
    file_iter = file_it
    live_jsons_dir = '/home/protick/ocsp_dns_django/ttldict/logs_final/live/node_code'
    run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
                 and '.json' in f and 'live_node' in f]
    lsts = []

    for l in run_jsons:
        lsts.append(l[: - len("-out.json")])

    for lst in lsts:
        try:
            cs, ics = parse_logs_ttl(exp_id=lst)
            send_telegram_msg("Done with parsing {}".format(lst))
        except Exception as e:
            print(e)
        # for key in r_pool:
        #     resolver_dict[key] = resolver_dict[key] + r_pool[key]

        # for key in r_i_t_r:
        #     req_id_to_resolvers[key][0].update(r_i_t_r[key][0])
        #     req_id_to_resolvers[key][1].update(r_i_t_r[key][1])

        # all_resolvers.update(a_r)
        # correct_resolvers.update(c_r)
        # incorrect_resolvers.update(i_r)
        #
        # correct_set.update(cs)
        # incorrect_set.update(ics)

    # resolver_count_list = []
    #
    # res_hits = 0
    # for k in resolver_dict:
    #     resolver_count_list.append((k, resolver_dict[k]))
    #     res_hits += resolver_dict[k]
    # resolver_count_list.sort(key=lambda x: -x[1])

    #incorrect_resolvers = incorrect_resolvers.difference(correct_resolvers)

    # total_resolvers = len(all_resolvers)
    # total_c_r = len(correct_resolvers)
    # total_i_r = len(incorrect_resolvers)
    # print("ans")
    # print("Total {}".format(total_resolvers))
    # print("Total Cr {}".format(total_c_r))
    # print("Total InC {}".format(total_i_r))


    # req_id_to_resolvers = defaultdict(lambda: [set(), set()])

    print("Total resolvers {}".format(len(list(final_dict.keys()))))
    # print("Total exit-nodes covered {}".format(len(list(req_id_to_resolvers.keys()))))

    data_final = {}
    data_final["Total_resolvers"] = len(list(final_dict.keys()))
    # data_final["Total_ex_nodes"] = len(list(req_id_to_resolvers.keys()))
    data_final["data"] = final_dict
    data_final["data_elaborate"] = final_dict_elaborate
    # ans = []
    # for key in final_dict:
    #     total = final_dict[key]["ic"] + final_dict[key]["c"]
    #     if total <= 0:
    #         continue
    #     ratio = final_dict[key]["ic"] / total
    #     if ratio > .85:
    #         ans.append(key)
    # print("Total InC {}".format(len(ans)))
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
    with open("final_asn_to_resolver.json", "w") as ouf:
        json.dump(resolver_asn_bonanza, fp=ouf)

    with open("req_id_to_bind_ips.json", "w") as ouf:
        json.dump(req_id_to_bind_ips, fp=ouf)

    with open("jaccard_index.json", "w") as ouf:
        json.dump(jaccard_index, fp=ouf)

    send_telegram_msg("Done with parsing phase 2")





def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])