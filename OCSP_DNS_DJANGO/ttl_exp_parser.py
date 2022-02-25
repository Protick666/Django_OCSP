import json
from collections import defaultdict
from os import listdir
from os.path import isfile, join
from datetime import datetime

url_live = 'ttlexp.exp.net-measurement.net'
event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]


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
                    time = time[: time.rfind(".")]
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
                except:
                    pass
    return d


def segment(lst, d1, d2):
    ans = []
    for e in lst:
        if d1 < e['date'] < d2:
            ans.append(e)
    return ans


def curate_time_segment(info, d1, d2):
    data = info["req"]
    ans = {}
    for req_id in data:
        lst = data[req_id]
        ans[req_id] = segment(lst, d1, d2)
    return ans


def preprocess_live_data(data):
    d = data['dict_of_phases']
    ans = {}
    for k in d:
        try:
            js = d[k]
            req_id = js['req_id']
            phase_1 = js['host-phase-1']
            phase_2 = js['host-phase-2']
            ans[req_id] = (phase_1, phase_2)
        except Exception as e:
            pass
    return ans


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

    bind_dir = 'ttldict/logs/{}/bind/'.format(exp_id)
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    apache_logs_phase_1_dir = 'ttldict/logs/{}/apache_1/'.format(exp_id)
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in listdir(apache_logs_phase_1_dir) if
                           isfile(join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = 'ttldict/logs/{}/apache_2/'.format(exp_id)
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in listdir(apache_logs_phase_2_dir) if
                           isfile(join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info = parse_bind_logs(exp_id=exp_id, bind_files=bind_files, resolver_pool=resolver_pool)
    # resolver_count_list = []
    #
    # res_hits = 0
    # for k in resolver_pool:
    #     resolver_count_list.append((k, resolver_pool[k]))
    #     res_hits += resolver_pool[k]
    # resolver_count_list.sort(key=lambda x: -x[1])

    apache_info_one = parse_apace_logs(exp_id=exp_id, apache_files=apache_logs_phase_1)
    apache_info_two = parse_apace_logs(exp_id=exp_id, apache_files=apache_logs_phase_2)

    lists_in_hand = [apache_info_one, apache_info_two, bind_info]

    for l in lists_in_hand:
        for k in event_strings:
            if k in l:
                l[k].sort(key=lambda x: x['date'])
        for k in l['req']:
            l['req'][k].sort(key=lambda x: x['date'])

    apache_phase_1_start = apache_info_one["phase1-start"][0]
    apache_phase_1_divider = apache_info_one["phase1-end"][0]
    apache_phase_2_start = apache_info_two["sleep-end"][0]
    apache_phase_2_end = apache_info_two["phase2-end"][0]

    bind_phase_1_start = bind_info["phase1-start"][0]
    bind_phase_1_end = bind_info["phase1-end"][0]
    bind_phase_2_start = bind_info["sleep-end"][0]
    bind_phase_2_end = bind_info["phase2-end"][0]

    bind_info_curated_first = curate_time_segment(bind_info, bind_phase_1_start, bind_phase_1_end)
    bind_info_curated_second = curate_time_segment(bind_info, bind_phase_2_start, bind_phase_2_end)
    # apache_info_one_phase_1 = curate_time_segment(apache_info_one, apache_phase_1_start, apache_phase_1_divider)
    # apache_info_one_phase_2 = curate_time_segment(apache_info_one, apache_phase_2_start, apache_phase_2_end)
    # apache_info_two_curated_phase_2 = curate_time_segment(apache_info_two, apache_phase_2_start, apache_phase_2_end)

    live_log = open("ttldict/logs/{}-ttl_exp.json".format(exp_id))
    live_data = preprocess_live_data(json.load(live_log))

    correct_set = set()
    incorrect_set = set()

    correct_resolvers = set()
    incorrect_resolvers = set()
    common_resolvers = set()

    for req_id in live_data:
        if live_data[req_id][0] == 1 and live_data[req_id][1] == 1:
            incorrect_set.add(req_id)
        elif live_data[req_id][0] == 1 and live_data[req_id][1] == 2:
            correct_set.add(req_id)

    print("Total reqs {}".format(len(list(live_data.keys()))))
    print("Total correct reqs {}".format(len(correct_set)))
    print("Total incorrect reqs {}".format(len(incorrect_set)))

    for req_id in correct_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, lum_resolvers)
        phase2_resolvers = get_non_lum_resolver_ips(bind_info_curated_second, req_id, lum_resolvers)
        correct_resolvers.update(phase1_resolvers.intersection(phase2_resolvers))

    for req_id in incorrect_set:
        phase1_resolvers = get_non_lum_resolver_ips(bind_info_curated_first, req_id, lum_resolvers)
        queries_from_second_phase = get_non_lum_resolver_ips(bind_info_curated_second, req_id, lum_resolvers)

        common_resolvers.update(phase1_resolvers.intersection(queries_from_second_phase))

        phase1_resolvers_incorrect = phase1_resolvers
        incorrect_resolvers.update(phase1_resolvers_incorrect)

    incorrect_resolvers = incorrect_resolvers.difference(correct_resolvers)
    incorrect_resolvers = incorrect_resolvers.difference(common_resolvers)

    all_resolvers = set()

    for key in resolver_pool:
        all_resolvers.add(key)

    return all_resolvers, correct_resolvers, incorrect_resolvers, resolver_pool


def master_calc():
    lsts = ['live1', 'live2']
    all_resolvers, correct_resolvers, incorrect_resolvers = set(), set(), set()

    resolver_dict = defaultdict(lambda : 0)

    for lst in lsts:
        a_r, c_r, i_r, r_pool = parse_logs_ttl(exp_id=lst)

        for key in r_pool:
            resolver_dict[key] = resolver_dict[key] + r_pool[key]

        all_resolvers.update(a_r)
        correct_resolvers.update(c_r)
        incorrect_resolvers.update(i_r)

    resolver_count_list = []

    res_hits = 0
    for k in resolver_dict:
        resolver_count_list.append((k, resolver_dict[k]))
        res_hits += resolver_dict[k]
    resolver_count_list.sort(key=lambda x: -x[1])

    incorrect_resolvers = incorrect_resolvers.difference(correct_resolvers)

    total_resolvers = len(all_resolvers)
    total_c_r = len(correct_resolvers)
    total_i_r = len(incorrect_resolvers)
    print("ans")
    print("Total {}".format(total_resolvers))
    print("Total Cr {}".format(total_c_r))
    print("Total InC {}".format(total_i_r))


    with open("lst.json", "w") as ouf:
        json.dump(resolver_count_list, fp=ouf, indent=2)

    send_telegram_msg("Done with parsing")

def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])