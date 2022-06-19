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
    BASE_URL = '/net/data/dns-ttl/new_run/'


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


def does_exp_id_match(line, exp_id_list):
    try:
        if ".live_zeus" not in line:
            return False, None
        st_index = line.find(".live_zeus")
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


def parse_bind_apache_logs(exp_id_list, files, is_bind=True, phase=None):

    for file in files:
        if is_bind:
            dump_directory = "preprocessed_ttl_log/bind/"
        else:
            dump_directory = "preprocessed_ttl_log/apache_{}/".format(phase)

        file_name = file.split("/")[-1]

        if not file_allowed(file_name):
            continue

        full_file_name = dump_directory + "{}.json".format(file_name)

        if os.path.isfile(full_file_name):
            continue

        Path(dump_directory).mkdir(parents=True, exist_ok=True)

        # with open(dump_directory + "{}.json".format(file_name), "w") as ouf:
        #     json.dump(things_to_store, fp=ouf)

        ans_dict = defaultdict(lambda: dict())
        req_id_to_resolvers = defaultdict(lambda: set())
        req_id_to_client_ips = defaultdict(lambda: set())
        with open(file) as FileObj:
            for line in FileObj:
                try:
                    if url_live not in line:
                        continue

                    is_exp_id_present, exp_id = does_exp_id_match(line, [])
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


        things_to_store = {}
        things_to_store["ans_dict"] = ans_dict
        things_to_store["req_id_to_resolvers"] = req_id_to_resolvers
        things_to_store["req_id_to_client_ips"] = req_id_to_client_ips

        with open(dump_directory + "{}.json".format(file_name), "w") as ouf:
            json.dump(things_to_store, fp=ouf, default=str)

        send_telegram_msg("*** Done with parsing Bind file {}".format(file))


def get_ip_list_from_encoded_set(str):
    if "," not in str:
        return []
    segments = str.split(",")
    ans = []
    for e in segments:
        ans.append(e[e.find("\'") + 1: e.rfind("\'")])
    return ans


def check_bind_logs():
    import ujson

    preprocessed_bind_dir = "/home/protick/ocsp_dns_django/preprocessed_ttl_log/bind/"
    bind_dir = preprocessed_bind_dir
    bind_preprocessed_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f and f.endswith(".json")]

    ans_dict_mother = {}
    req_id_to_resolvers_mother = defaultdict(lambda: set())

    for file in bind_preprocessed_files:
        try:
            f = open(file)
            d = ujson.load(f)
        except Exception as e:
            send_telegram_msg("*** Jhamela postprocessing Bind file {}".format(file))


def get_set_exp_id_temp_file(exp_id, dir_extension, get=True, data={}, allowed_ttl=-1):
    full_dir = "temp_dump_{}/{}".format(allowed_ttl, dir_extension)
    full_file_path = "{}/{}.json".format(full_dir, exp_id)
    Path(full_dir).mkdir(parents=True, exist_ok=True)

    if get:
        if os.path.isfile(full_file_path):
            f = open(full_file_path)
            d = ujson.load(f)
            return d
        else:
            empty_dict = {}
            with open(full_file_path, "w") as ouf:
                json.dump(empty_dict, fp=ouf)
            return empty_dict
    else:
        with open(full_file_path, "w") as ouf:
            json.dump(data, fp=ouf)


def file_allowed(file_name):
    try:
        comp_time = 1655352765
        end_time = 1655545407
        # query.log.1649733454937.json
        time_Seg = int(file_name.split(".")[-1][:10])
        return end_time >= time_Seg >= comp_time
    except:
        return False


# TODO set TTL 60, preprocess v2


def post_process_bind_logs_v2(allowed_ttl):
    preprocessed_bind_dir = "/home/protick/ocsp_dns_django/preprocessed_ttl_log/bind/"
    bind_dir = preprocessed_bind_dir
    bind_preprocessed_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f and f.endswith(".json") and "query" in f]
    # TODO
    # bind_preprocessed_files = bind_preprocessed_files[:10]
    total_bind_files = len(bind_preprocessed_files)
    import time
    dir_extension = int(time.time())
    req_id_to_resolvers_mother = defaultdict(lambda: set())

    file_index = 0
    for file in bind_preprocessed_files:
        file_index += 1

        file_name = file.split("/")[-1]
        # if not file_allowed(file_name):
        #     # send_telegram_msg("*** Skipping Bind file {}".format(file))
        #     continue

        try:
            f = open(file)
            d = ujson.load(f)
        except Exception:
            continue
        ans_dict = d["ans_dict"]
        req_id_to_resolvers = d["req_id_to_resolvers"]

        for exp_id in ans_dict:
            if "live_zeus_{}_".format(allowed_ttl) not in exp_id:
                continue

            ans_dict_prev = get_set_exp_id_temp_file(exp_id=exp_id, dir_extension=dir_extension, get=True, allowed_ttl=allowed_ttl)

            if "req" not in ans_dict_prev:
                ans_dict_prev["req"] = {}

            nested_dict = ans_dict[exp_id]

            if "req" in nested_dict:
                for identifier in nested_dict["req"]:
                    if identifier not in ans_dict_prev["req"]:
                        ans_dict_prev["req"][identifier] = list()
                    for e in nested_dict["req"][identifier]:
                        ans_dict_prev["req"][identifier].append(e)

            for key in nested_dict:
                if key == "req":
                    continue
                if key not in ans_dict_prev:
                    ans_dict_prev[key] = list()
                for e in nested_dict[key]:
                    ans_dict_prev[key].append(e)
            get_set_exp_id_temp_file(exp_id=exp_id, dir_extension=dir_extension, get=False, data=ans_dict_prev, allowed_ttl=allowed_ttl)

        l = 0
        for identifier in req_id_to_resolvers:
            ip_list = get_ip_list_from_encoded_set(req_id_to_resolvers[identifier])
            l += len(ip_list)
            for element in ip_list:
                req_id_to_resolvers_mother[identifier].add(element)

        try:
            f.close()
        except:
            pass
        send_telegram_msg("*** Finised postprocessing Bind file {}, index {}/{},  ip list: {}".format(file, file_index, total_bind_files, l))

    dump_directory = "temp_dump_{}/".format(allowed_ttl)
    Path(dump_directory).mkdir(parents=True, exist_ok=True)

    temp_dict = {}
    for identifier in req_id_to_resolvers_mother:
        temp_dict[identifier] = list(req_id_to_resolvers_mother[identifier])
    with open(dump_directory + "{}.json".format("req_id_to_resolvers_mother"), "w") as ouf:
        json.dump(temp_dict, fp=ouf)
    send_telegram_msg("*** Finished Everything, directory {}".format(dir_extension))


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


def parse_logs_together(allowed_exp_ids=None):
    bind_dir = BASE_URL + 'bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files, is_bind=True)


def is_allowed(element, lst):
    for e in lst:
        if element == e:
            return True
    return False

# max_retries()


def send_telegram_msg(msg):
    try:
        import telegram_send
        msg = "v2 " + msg
        telegram_send.send(messages=[msg])
    except Exception as e:
        pass

