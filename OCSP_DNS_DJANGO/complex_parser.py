import json
from collections import defaultdict
from os import listdir
from os.path import isfile, join
from datetime import datetime, timedelta
import pyasn
from OCSP_DNS_DJANGO.local import LOCAL
from OCSP_DNS_DJANGO.tools import AS2ISP
import os

exp_threshold_list = [43, 49, 55, 58]
instance_id = int(os.environ['instance_id'])
exp_threshold_for_this_server = exp_threshold_list[instance_id - 1]

as2isp = AS2ISP()

org_dict_2 = {}
def get_org(asn):
    if asn in org_dict_2:
        return org_dict_2[asn]

    org = str(as2isp.getISP("20221212", asn)[0])
    cntry = str(as2isp.getISP("20221212", asn)[1])
    org.replace("\"", "")
    cntry.replace("\"", "")
    return org, cntry


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


ip_to_asn = {}
def get_asn(ip):
    if ip in ip_to_asn:
        return ip_to_asn[ip]

    try:
        return asndb.lookup(ip)[0]
    except:
        return ""

url_live = 'ttlexp.exp.net-measurement.net'
event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]

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


'''
Global:
resolver_to_ips: resolver -> ips from req ids that hit those resolvers
                                *** not only considered resolvers from our method ***
'''
resolver_to_ips = defaultdict(lambda: set())

if LOCAL:
    BASE_URL = '/Users/protick.bhowmick/PriyoRepos/OCSP_DNS_DJANGO/logs_final/'
else:
    BASE_URL = '/home/protick/node_code/rec_duo_complex_60/'

BASE_URL_BIND_APACHE = "/net/data/dns-ttl/"


# OUTER

def initiate_per_threshold_global_sets():
    global telemetry_count
    global final_dict
    global final_dict_elaborate
    global resolver_to_ips

    telemetry_count = {}
    final_dict = {}
    final_dict_elaborate = {}
    resolver_to_ips = defaultdict(lambda: set())


def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def does_exp_id_match(line, exp_id_list):
    #.live_recpronew_43_1000_21.

    prefix = ".live_recpronew_{}_".format(exp_threshold_for_this_server)

    try:
        if prefix not in line:
            return False, None
        st_index = line.find(prefix)
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
    datetime_object = datetime.strptime(time, '%d/%b/%Y:%H:%M:%S')

    meta = {}
    meta["date"] = datetime_object
    meta["url"] = url
    meta["client_ip"] = client_ip

    return meta


def parse_bind_apache_logs(exp_id_list, files, is_bind=True):
    ans_dict = defaultdict(lambda: dict())

    tot_files = len(files)
    index = 0
    for file in files:
        index += 1
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

        send_telegram_msg("*** Done with parsing Bind file {}".format(file))
        send_telegram_msg("Done with isbind {}, {}/{}".format(is_bind, index, tot_files))
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
            server_time_1 = js['1-time']
            server_time_2 = js['2-time']
            ans[req_id] = (phase_1, phase_2, js['asn'], server_time_1, server_time_2)
            req_id_to_ip_hash[req_id] = js['ip_hash']
        except Exception as e:
            print('preprocess_live_data', e)
    return ans, req_id_to_ip_hash


def get_ip_hit_time_tuple(req_id, apache_info_one, apache_info_two):
    phase_1_timestamp, phase_2_timestamp = "N/A", "N/A"

    try:
        phase_1_list = apache_info_one[req_id]
        phase_2_list = apache_info_two[req_id]

        try:
            phase_1_timestamp = datetime.timestamp(phase_1_list[0]['date'])
        except:
            pass
        try:
            phase_2_timestamp = datetime.timestamp(phase_2_list[0]['date'])
        except:
            pass
    except:
        pass

    return phase_1_timestamp, phase_2_timestamp


def get_non_lum_resolver_ips(bind_info, req_id, lum_resolvers):
    lst = bind_info[req_id]  # ['resolver_ip']
    resolvers = set()
    resolver_to_timestamp = {}
    for e in lst:
        ip = e['resolver_ip']
        timestamp = datetime.timestamp(e['date'])
        if ip not in resolver_to_timestamp:
            resolver_to_timestamp[ip] = timestamp
        if ip not in lum_resolvers:
            resolvers.add(ip)
    return resolvers, resolver_to_timestamp


def parse_logs_together(allowed_exp_ids):
    bind_dir = BASE_URL_BIND_APACHE + 'bind/'
    bind_files = [bind_dir + f for f in listdir(bind_dir) if isfile(join(bind_dir, f)) and '.gz' not in f]

    apache_logs_phase_1_dir = BASE_URL_BIND_APACHE + 'apache1/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in listdir(apache_logs_phase_1_dir) if
                           isfile(join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = BASE_URL_BIND_APACHE + 'apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in listdir(apache_logs_phase_2_dir) if
                           isfile(join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files, is_bind=True)
    apache_info_one_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_1, is_bind=False)
    apache_info_two_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_2, is_bind=False)

    return bind_info_global, apache_info_one_global, apache_info_two_global


def log_considered_resolvers(considered_resolvers, req_id, ip_hash, type_key,
                             server_time_1, server_time_2, phase1_resolver_to_timestamp,
                             phase2_resolver_to_timestamp, phase_1_apache_hit_timestamp,
                             phase_2_apache_hit_timestamp):

    for key in considered_resolvers:
        rt1, rt2 = "N/A", "N/A"
        if key in phase1_resolver_to_timestamp:
            rt1 = phase1_resolver_to_timestamp[key]
        if key in phase2_resolver_to_timestamp:
            rt2 = phase2_resolver_to_timestamp[key]

        if key not in final_dict:
            final_dict[key] = {"reduce": 0, "pro": 0, "normal": 0}
        if key not in final_dict_elaborate:
            final_dict_elaborate[key] = {"reduce": list(), "pro": list(), "normal": list()}

        final_dict[key][type_key] = 1 + final_dict[key][type_key]
        # req_id, ip_hash, st1, st2, rt1, rt2, wt1, wt2
        final_dict_elaborate[key][type_key].append((req_id, ip_hash, server_time_1, server_time_2,
                                                    rt1, rt2, phase_1_apache_hit_timestamp, phase_2_apache_hit_timestamp))


def parse_logs_ttl(exp_id, bind_info, apache_info_one, apache_info_two, exp_threshold):
    try:
        mama = 1
        lists_in_hand = [apache_info_one, apache_info_two, bind_info]

        for l in lists_in_hand:
            for k in event_strings:
                if k in l:
                    l[k].sort(key=lambda x: x['date'])
            if 'req' in l:
                for k in l['req']:
                    l['req'][k].sort(key=lambda x: x['date'])

        bind_phase_1_start = bind_info["phase1-start"][0]['date']
        bind_phase_1_end = bind_info["phase1-end"][0]['date']
        bind_phase_2_start = bind_info["sleep-end"][0]['date']
        bind_phase_2_end = bind_info["phase2-end"][0]['date']

        bind_info_curated_first = curate_time_segment(bind_info, bind_phase_1_start, bind_phase_1_end)
        bind_info_curated_second = curate_time_segment(bind_info, bind_phase_2_start, bind_phase_2_end)

        apache_info_curated_first = curate_time_segment(apache_info_one,
                                                        bind_phase_1_start - timedelta(minutes=.5),
                                                        bind_phase_1_end + timedelta(minutes=.5))
        apache_info_curated_second = curate_time_segment(apache_info_two,
                                                         bind_phase_2_start - timedelta(minutes=.5),
                                                         bind_phase_2_end + timedelta(minutes=.5))

        apache_info_curated_second_connecting_to_one = curate_time_segment(apache_info_one,
                                                         bind_phase_2_start - timedelta(minutes=.5),
                                                         bind_phase_2_end + timedelta(minutes=.5))

        # live_recpronew_thresh_iteration_bucket
        # live_recpronew_43_1038_10

        segments = exp_id.split("_")
        exp_iteration = int(segments[-2])

        # /home/protick/node_code/rec_duo_complex_60/43/1000/live_recpronew_43_1000_22-out.json
        live_log = open(BASE_URL + "{}/{}/{}-out.json".format(exp_threshold, exp_iteration, exp_id))

        live_data, req_id_to_ip_hash = preprocess_live_data(json.load(live_log))

        case_1_set = set()
        case_2_set = set()

        # case 1 -> exitnode connects to new (potential less cache)
        # case 2 -> exitnode connects to old (potential proactive caching)
        # (phase_1, phase_2, js['asn'], server_time_1, server_time_2)
        for req_id in live_data:
            # case 2
            if live_data[req_id][0] == 1 and live_data[req_id][1] == 1:
                case_2_set.add(req_id)
            # case 1
            elif live_data[req_id][0] == 1 and live_data[req_id][1] == 2:
                case_1_set.add(req_id)

        # msg_to_send = "case 1 set {}, case 2 set {}".format(len(case_1_set), len(case_2_set))
        # send_telegram_msg(msg_to_send)

        # TODO resume from here
        for req_id in case_1_set:
            phase1_resolvers, phase1_resolver_to_timestamp = get_non_lum_resolver_ips(bind_info_curated_first, req_id,
                                                                                      [])
            phase2_resolvers, phase2_resolver_to_timestamp = get_non_lum_resolver_ips(bind_info_curated_second, req_id,
                                                                                      [])

            considered_resolvers = phase1_resolvers.intersection(phase2_resolvers)
            server_time_1, server_time_2 = live_data[req_id][3], live_data[req_id][4]
            phase_1_apache_hit_timestamp, phase_2_apache_hit_timestamp = get_ip_hit_time_tuple(req_id,
                                                                                               apache_info_curated_first,
                                                                                               apache_info_curated_second)

            log_considered_resolvers(considered_resolvers=considered_resolvers,
                                     req_id=req_id,
                                     ip_hash=req_id_to_ip_hash[req_id],
                                     type_key="reduce",
                                     server_time_1=server_time_1,
                                     server_time_2=server_time_2,
                                     phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                     phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                     phase_1_apache_hit_timestamp=phase_1_apache_hit_timestamp,
                                     phase_2_apache_hit_timestamp=phase_2_apache_hit_timestamp
                                     )

        for req_id in case_2_set:
            phase1_resolvers, phase1_resolver_to_timestamp = get_non_lum_resolver_ips(bind_info_curated_first, req_id,
                                                                                      [])
            phase2_resolvers, phase2_resolver_to_timestamp = get_non_lum_resolver_ips(bind_info_curated_second, req_id,
                                                                                      [])
            considered_resolvers = phase1_resolvers.intersection(phase2_resolvers)
            normal_resolvers = phase1_resolvers.difference(phase2_resolvers)
            server_time_1, server_time_2 = live_data[req_id][3], live_data[req_id][4]
            phase_1_apache_hit_timestamp, phase_2_apache_hit_timestamp = get_ip_hit_time_tuple(req_id,
                                                                                               apache_info_curated_first,
                                                                                               apache_info_curated_second_connecting_to_one)
            # msg_to_send = "Got case 2, considered resolvers {}, normal resolvers {}".format(len(considered_resolvers),
            #                                                                                 len(normal_resolvers))
            # send_telegram_msg(msg_to_send)

            log_considered_resolvers(considered_resolvers=considered_resolvers,
                                     req_id=req_id,
                                     ip_hash=req_id_to_ip_hash[req_id],
                                     type_key="pro",
                                     server_time_1=server_time_1,
                                     server_time_2=server_time_2,
                                     phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                     phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                     phase_1_apache_hit_timestamp=phase_1_apache_hit_timestamp,
                                     phase_2_apache_hit_timestamp=phase_2_apache_hit_timestamp
                                     )

            log_considered_resolvers(considered_resolvers=normal_resolvers,
                                     req_id=req_id,
                                     ip_hash=req_id_to_ip_hash[req_id],
                                     type_key="normal",
                                     server_time_1=server_time_1,
                                     server_time_2=server_time_2,
                                     phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                     phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                     phase_1_apache_hit_timestamp=phase_1_apache_hit_timestamp,
                                     phase_2_apache_hit_timestamp=phase_2_apache_hit_timestamp
                                     )

        return case_1_set, case_2_set
    except Exception as e:
        pass


def get_all_asns(file_iter):
    live_jsons_dir = BASE_URL + 'live/node_code/'.format(file_iter)
    run_jsons = [f for f in listdir(live_jsons_dir) if isfile(join(live_jsons_dir, f))
                 and '.json' in f and 'live_node' in f]

    asn_set = set()
    for e in run_jsons:
        live_log = open(BASE_URL + "live/node_code/{}".format(file_iter, e))
        live_data, req_id_to_ip_hash, _, _ = preprocess_live_data(json.load(live_log))
        for key in live_data:
            asn_set.add(live_data[key][2])

    with open("ttl_exp_asn_list.json", "w") as ouf:
        json.dump(list(asn_set), fp=ouf)


def parc():
    get_leaf_files(BASE_URL + 'live/results')


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

    # TODO TADAaa
    bind_info_global, apache_info_one_global, apache_info_two_global = parse_logs_together(allowed_exp_ids=[])
    send_telegram_msg("Done with parsing bind/apache logs")

    exp_to_file_list = defaultdict(lambda: list())
    for exp_threshold in exp_threshold_list:
        leaf_files_unfiltered = get_leaf_files(BASE_URL + '{}/'.format(exp_threshold))
        leaf_files_filtered = [e.split("/")[-1] for e in leaf_files_unfiltered]
        leaf_files_filtered = [e for e in leaf_files_filtered if ".json" in e]
        exp_to_file_list[exp_threshold] = leaf_files_filtered

    # TODO TADAaa
    for exp_threshold in [exp_threshold_for_this_server]:
        pp = []
        exp_id_list = []
        for element in exp_to_file_list[exp_threshold]:
            exp_id_list.append(element[: - len("-out.json")])
        initiate_per_threshold_global_sets()

        for exp_id in exp_id_list:
            try:
                # TODO
                _, _ = parse_logs_ttl(exp_id=exp_id,
                                     bind_info=bind_info_global[exp_id],
                                     apache_info_one=apache_info_one_global[exp_id],
                                     apache_info_two=apache_info_two_global[exp_id],
                                     exp_threshold=exp_threshold)
            except Exception as e:
                pp.append('master_calc {} {}'.format(e, exp_id))
                print('master_calc ', e, exp_id)

        send_telegram_msg("Done with parsing Threshold live files")

        from pathlib import Path
        parent_path = 'results_proactive_complex_v5/{}/'.format(exp_threshold)
        Path(parent_path).mkdir(parents=True, exist_ok=True)

        data_final = {}
        data_final["Total_resolvers"] = len(list(final_dict.keys()))
        # data_final["Total_ex_nodes"] = len(list(req_id_to_resolvers.keys()))
        data_final["data"] = final_dict
        data_final["data_elaborate"] = final_dict_elaborate

        with open(parent_path + "final_data.json", "w") as ouf:
            json.dump(data_final, fp=ouf)

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
        with open(parent_path + "final_resolver_to_asn.json", "w") as ouf:
            json.dump(resolver_asn_bonanza, fp=ouf)

        try:
            local_public_analyzer(resolver_asn_bonanza, parent_path)
        except Exception as e:
            print(e)
            pass

        with open(parent_path + "telemetry_count.json", "w") as ouf:
            json.dump(telemetry_count, fp=ouf)

        with open(parent_path + "error_desc.json", "w") as ouf:
            json.dump(pp, fp=ouf)

        send_telegram_msg("Done with parsing Threshold final {}".format(exp_threshold))


def send_telegram_msg(msg):
    msg = "Complex {}: {}".format(exp_threshold_for_this_server, msg)
    try:
        import telegram_send
        telegram_send.send(messages=[msg])
    except Exception as e:
        pass
