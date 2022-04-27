import json
from collections import defaultdict
from os import listdir
from os.path import isfile, join
from datetime import datetime
import pyasn
from OCSP_DNS_DJANGO.local import LOCAL
from OCSP_DNS_DJANGO.tools import AS2ISP
from pathlib import Path
import os
import ujson

# {} -> resolver_ip -> req_id -> [5]

resolver_to_middle_req = defaultdict(lambda: defaultdict(lambda: list()))

resolver_to_last_req = defaultdict(lambda: dict())

# banned live_zeus_5_404 -> live_zeus_5_525 # live_zeus_5_499 porjonto allowed

as2isp = AS2ISP()


def get_org(asn):
    org = str(as2isp.getISP("20221212", asn)[0])
    cntry = str(as2isp.getISP("20221212", asn)[1])
    org.replace("\"", "")
    cntry.replace("\"", "")
    return org, cntry


def get_live_file_name(ttl):
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
    try:
        return asndb.lookup(ip)[0]
    except:
        return ""

incorrect_asn_set = set()

#file_iter = None
# 5c77f2fa-5e57-4e55-baaa-45198f56ac7f1650875806358.live_recpro_60_1014_55.134128.245.ttlexp.exp.net-measurement.net
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

done globally for all TTL
'''



'''
Global:
req_id_to_client_ips: both phases!
'''



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

# all asns that reached both phases**
global_asn_set = set()

if LOCAL:
    BASE_URL = '/Users/protick.bhowmick/PriyoRepos/OCSP_DNS_DJANGO/logs_final/'
else:
    BASE_URL = '/home/protick/ocsp_dns_django/ttldict/logs_final_v2/'


# OUTER

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


def find_ttl(str):
    segments = str.split("_")
    return int(segments[-1])

def does_exp_id_match(line, exp_id_list):
    try:
        if ".live_recpro_" not in line:
            return False, None
        st_index = line.find(".live_recpro_")
        sub = line[st_index + 1:]
        sub = sub.split(".")[0]
        return True, sub
    except Exception:
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


mid_req_master_dict = defaultdict(lambda: defaultdict(lambda: list()))

def file_allowed(file_name):
    try:
        comp_time = 1650775654
        end_time =  1650909407
        time_Seg = int(file_name.split(".")[-1][:10])
        return end_time >= time_Seg >= comp_time
    except:
        return False

# 5c77f2fa-5e57-4e55-baaa-45198f56ac7f1650875806358.live_recpro_60_1014_55.134128.245.ttlexp.exp.net-measurement.net

def parse_bind_apache_logs(exp_id_list, files, is_bind=True, phase=None):
    p = 0
    if is_bind:
        dump_directory = "preprocessed_proactive_req_log/bind/"
    else:
        dump_directory = "preprocessed_proactive_req_log/apache_{}/".format(phase)
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    tot_files = len(files)
    index = 0
    for file in files:
        index += 1
        file_name = file.split("/")[-1]

        if not file_allowed(file_name):
            continue

        with open(file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue
                    is_exp_id_present, exp_id = does_exp_id_match(line, [])

                    if not is_exp_id_present:
                        continue

                    # ttl_here = find_ttl(exp_id)
                    # if ttl_here not in mid_req_master_dict:
                    #     mid_req_master_dict[ttl_here] = defaultdict(lambda: defaultdict(lambda: list()))

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
                        pass
                    else:
                        identifier = str(url.split(".")[0])
                        mid_req_master_dict[meta["resolver_ip"]][identifier].append(int(datetime.timestamp(meta["date"])))
                        p = max(p, len(mid_req_master_dict[meta["resolver_ip"]][identifier]))

                except Exception as e:
                    print('parse bind apache logs ', e)
        send_telegram_msg("*** Done with parsing Bind file {},  {}/{}".format(file, index, tot_files))

    print("PPP {}".format(p))
    with open(dump_directory + "{}.json".format("proactive_req"), "w") as ouf:
        json.dump(mid_req_master_dict, fp=ouf)

    send_telegram_msg("*** Done with parsing Everything Yo Yo")



def fix_it():
    # mid_req_master_dict[ttl_here][meta["resolver_ip"]][identifier].append(int(datetime.timestamp(meta["date"])))
    dump_directory = "preprocessed_proactive_req_log/bind/"
    f = open(dump_directory + "{}.json".format("proactive_req"))
    d = json.load(f)

    mother_dict = defaultdict(lambda: defaultdict(lambda: list()))

    for ttl in d:
        for resolver in d[ttl]:
            for identifier in d[ttl][resolver]:
                for element in d[ttl][resolver][identifier]:
                    mother_dict[resolver][identifier].append(element)

    with open(dump_directory + "{}.json".format("corrected_proactive_req"), "w") as ouf:
        json.dump(mother_dict, fp=ouf)



def get_non_lum_resolver_ips(bind_info, req_id, lum_resolvers):
    lst = bind_info[req_id]  # ['resolver_ip']
    resolvers = set()
    for e in lst:
        ip = e['resolver_ip']
        if ip not in lum_resolvers:
            resolvers.add(ip)
    return resolvers


def parse_live_logs():
    directory = "/home/protick/node_code/proactive_duo/results_60/"
    data_files = [directory + f for f in listdir(directory) if isfile(join(directory, f)) and '.json' in f]

    send_telegram_msg("*** Starting live logs")

    master_live_dict = {}
    for file in data_files:
        f = open(file)
        d = ujson.load(f)
        d = d["dict_of_phases"]
        for req_id in d:
            for num in d[req_id]:
                try:
                    url = d[req_id][num]["req_url"]
                    t1 = d[req_id][num]["1-time"]
                    t2 = d[req_id][num]["2-time"]
                    diff = t2 - t1
                    identifier = str(url.split(".")[0])
                    master_live_dict[identifier] = {
                        "url": url,
                        "t1": t1,
                        "t2": t2,
                        "diff": diff,
                    }
                except:
                    pass
        send_telegram_msg("*** Done with live log {}".format(file))

    dump_directory = "preprocessed_proactive_req_log/bind/"
    with open(dump_directory + "{}.json".format("proactive_req_live_file"), "w") as ouf:
        json.dump(master_live_dict, fp=ouf)

    send_telegram_msg("*** Done with live logs")


def parse_logs_together(allowed_exp_ids=None):
    bind_dir = BASE_URL + 'bind/bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]
    parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files, is_bind=True)
    # parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_1, is_bind=False, phase=1)
    # parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_2, is_bind=False, phase=2)





def filter_time_series_hits(lst):
    list_to_work_on = []
    for e in lst:
        list_to_work_on.append(int(e))
    list_to_work_on.sort()

    if len(list_to_work_on) == 1:
        return []
    final_list = []

    final_list.append(0)
    init_stamp = list_to_work_on[0]
    to_cmp = list_to_work_on[0]
    init_delta = 20
    for index in range(1, len(list_to_work_on)):
        if list_to_work_on[index] - to_cmp <= init_delta:
            continue
        else:
            final_list.append(list_to_work_on[index] - init_stamp)
            to_cmp = list_to_work_on[index]
            init_delta = 1

    final_list = final_list[1: ]
    return final_list


def filter_data(data, live_data):
    data_cp = dict(data)
    for identifier in list(data_cp.keys()):
        # if identifier not in live_data:
        #     data_cp.pop(identifier, None)
        #     continue
        curated_list = filter_time_series_hits(data_cp[identifier])
        if len(curated_list) == 0:
            data_cp.pop(identifier, None)
        else:
            data_cp[identifier] = curated_list
    if len(list(data_cp.keys())) == 0:
        return None
    return data_cp


def filter_out_multiple_resolvers():
    source_directory = "preprocessed_proactive_req_log/bind/"
    f = open("{}{}".format(source_directory, "proactive_req.json"))
    d = json.load(f)
    send_telegram_msg("loaded !!")

    f = open("{}{}".format(source_directory, "proactive_req_live_file.json"))
    live_data = json.load(f)
    # master_live_dict[identifier] = {
    #     "url": url,
    #     "t1": t1,
    #     "t2": t2,
    #     "diff": diff,
    # }

    data = d
    print(len(data.keys()))
    for resolver in list(data.keys()):
        nested_data = filter_data(data[resolver], live_data)
        if nested_data is None:
            data.pop(resolver, None)
        else:
            data[resolver] = nested_data

    with open(source_directory + "{}.json".format("proactive_req_post_{}".format(60)), "w") as ouf:
        json.dump(data, fp=ouf)
    send_telegram_msg("Done")


def is_allowed(element, lst):
    for e in lst:
        if element == e:
            return True
    return False

# max_retries()


def send_telegram_msg(msg):
    try:
        import telegram_send
        telegram_send.send(messages=[msg])
    except Exception as e:
        pass


def inito():
    parse_logs_together()
    parse_live_logs()
    filter_out_multiple_resolvers()

