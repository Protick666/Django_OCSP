from OCSP_DNS_DJANGO.local import LOCAL
import json
import random
from OCSP_DNS_DJANGO.models import *
import redis


def get_ocsp_hosts():
    # TODO test
    ocsp_hosts = ocsp_url_db.objects.all()

    host_to_id = {}

    for e in ocsp_hosts:
        host_to_id[e.url] = e.id

    return [e.url for e in ocsp_hosts], host_to_id


def get_ocsp_hosts_v2(redis_host):
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    return [item.decode() for item in ocsp_urls_set]

def choose_asn_number_per_country(number):
    if LOCAL:
        return min(number, 1)
    else:
        return max(int(number * .15), 1)


def get_total_cert_per_ocsp_url():
    if LOCAL:
        return 10
    else:
        return 20


def choose_candidate_asns():
    f = open('global_tuple_list.json')
    asn_list = json.load(f)
    # asn_cn_tuple_list = [(e, "N/A") for e in asn_list]
    return asn_list
    '''
    
    prev implementation
    '''
    #f = open('luminati_country_to_asn.json')
    # country_to_asn_list = json.load(f)
    #
    # chosen_asn_outer = []
    # for country in country_to_asn_list:
    #     asn_list = country_to_asn_list[country]
    #     total_available_asn = len(asn_list)
    #     allowed_asn_number = choose_asn_number_per_country(total_available_asn)
    #     chosen_asn_s = random.sample(asn_list, allowed_asn_number)
    #     chosen_asn_s = [(element[0], country) for element in chosen_asn_s]
    #     chosen_asn_outer = chosen_asn_outer + chosen_asn_s
    #
    # if LOCAL:
    #     chosen_asn_outer = chosen_asn_outer[0: 10]
    # return chosen_asn_outer


def choose_all_available_asns():
    f = open('OCSP_DNS_DJANGO/luminati_data/successful_asns.json')
    asn_list = json.load(f)
    #print(len(asn_list))
    return asn_list


def choose_hops(only_asns=False, ban_list=[]):
    # 17844
    f = open("ttl_data_set-live-local-False.json")
    d = json.load(f)
    s = set()
    for e in d:
        s.add(e[0])
    a = []

    index = 1
    for e in s:
        a.append((e, index))
        index += 1
    return a
    # asns = choose_candidate_asns()
    # return asns
    # dash_board_asns = [element[0] for element in dash_board_asns]
    # if LOCAL:
    #     dash_board_split = 10
    # else:
    #     dash_board_split = 150
    #
    # dash_board_asns = random.sample(dash_board_asns, dash_board_split)

    ## TODO masssive: rebuild this json after scanning
    # f = open('OCSP_DNS_DJANGO/luminati_data/successful_asns.json')
    # if LOCAL:
    #     global_asn_split = 10
    # else:
    #     global_asn_split = 800
    # asn_list = json.load(f)
    # asn_list = random.sample(asn_list, global_asn_split)
    # asn_list = []
    # all_asns = dash_board_asns + asn_list
    # all_asns = [(element, ASN) for element in all_asns]
    #
    # if only_asns:
    #     return all_asns


    # f = open("OCSP_DNS_DJANGO/countries.json")
    # d = json.load(f)
    # country_codes = []
    # for e in d:
    #     country_codes.append(d[e]["cc"])
    # if LOCAL:
    #     country_split = 10
    # else:
    #     country_split = 50
    # country_codes = random.sample(country_codes, country_split)
    # all_countries = [(element, CN) for element in country_codes]
    #
    # return all_asns + all_countries


def get_ocsp_url_number(total_number):
    if LOCAL:
        return total_number
    else:
        return total_number


def choose_hops_for_ttl_exp(file_date):
    f = open("available_asns-{}.json".format(file_date))
    import ujson

    asns = ujson.load(f)
    if LOCAL:
        return asns[:40]
    else:
        return asns

# TODO check


def get_all_asn_list_with_prefix_count():
    tweets = []
    asn_list = set()
    asn_to_prefix_count = {}
    asn_to_address_count = {}
    for line in open('asns_full_info.json', 'r'):
        tweets.append(json.loads(line))

    total_prefixes = 0
    total_addresses = 0
    for a in tweets:
        total_prefixes += a['announcing']['numberPrefixes']
        total_addresses += a['announcing']['numberAddresses']

    for a in tweets:
        asn_list.add(a['asn'])
        asn_to_prefix_count[a['asn']] = a['announcing']['numberPrefixes']
        asn_to_address_count[a['asn']] = a['announcing']['numberAddresses']

    asn_to_prefix_count['all'] = total_prefixes
    asn_to_address_count['all'] = total_addresses

    return list(asn_list), asn_to_prefix_count, asn_to_address_count


def choose_hops_for_ttl_exp_v2(total_requests, asn_list, asn_to_prefix_count):
    lst = []

    for asn in asn_list:
        if asn not in asn_to_prefix_count:
            print(asn)
            continue
        if asn_to_prefix_count[asn] == 0:
            continue
        allotment = (asn_to_prefix_count[asn] / asn_to_prefix_count['all']) * total_requests
        allotment = max(min(allotment, 5), 50)
        lst.append((asn, allotment))

    import random
    random.shuffle(lst)

    flattened_list = []
    id = 1
    for e in lst:
        for i in range(e[1]):
            flattened_list.append((e[0], id))
            id += 1

    random.shuffle(flattened_list)
    return flattened_list

def choose_hops_for_ttl_exp_v3(total_requests, asn_to_cnt_tup, asn_to_address_count):
    lst = []
    asn_to_cnt_tup.sort()
    n = len(asn_to_cnt_tup)
    minor_list = asn_to_cnt_tup[: int(n * .8)]
    major_list = asn_to_cnt_tup[int(n * .8): ]
    minor_tot, major_tot = 0, 0
    for e in major_list:
        major_tot += e[0]
    for e in minor_list:
        minor_tot += e[0]

    for cnt, asn in minor_list:
        if asn not in asn_to_address_count:
            continue
        if asn_to_address_count[asn] == 0:
            continue
        allotment = (asn_to_address_count[asn] / minor_tot) * total_requests
        allotment = max(min(allotment, 1), 15)
        lst.append((asn, allotment))

    for cnt, asn in major_list:
        if asn not in asn_to_address_count:
            continue
        if asn_to_address_count[asn] == 0:
            continue
        allotment = (asn_to_address_count[asn] / major_tot) * int(total_requests/4)
        allotment = max(min(allotment, 18), 40)
        lst.append((asn, allotment))

    import random
    random.shuffle(lst)

    flattened_list = []
    id = 1
    for e in lst:
        for i in range(e[1]):
            flattened_list.append((e[0], id))
            id += 1

    random.shuffle(flattened_list)
    return flattened_list


def get_local_asn_list():
    f = open("ttl_data_set-live-local-False.json")
    d = json.load(f)
    asn_set = set()
    for e in d:
        asn_set.add(e[0])

    asn_list = list(asn_set)
    return asn_list

def create_lst_both(total_requests):
    asn_list, asn_to_prefix_count, asn_to_address_count = get_all_asn_list_with_prefix_count()

    local_asn_list = get_local_asn_list()

    # print("Local ", len(local_asn_list))
    print("Global ", len(asn_list))

    # asn_to_cnt_tup = []
    # for asn in asn_list:
    #     if asn_to_address_count[asn] == 0:
    #         continue
    #     asn_to_cnt_tup.append((asn_to_address_count[asn], asn))
    # asn_to_cnt_tup.sort()

    # asn_list_curated = []
    # for asn in asn_list:
    #     if asn in local_asn_list:
    #         continue
    #     asn_list_curated.append(asn)
    # id = 1
    # ans = []
    # for e in asn_list:
    #     if asn_to_address_count[e] == 0:
    #         continue
    #     ans.append((e, id))
    #     id = id + 1

    # with open("ttl_data_set-live-v4-local-{}.json".format(LOCAL), "w") as ouf:
    #     json.dump(ans, fp=ouf)

    # local_list = choose_hops_for_ttl_exp_v2(total_requests=total_requests, asn_list=local_asn_list,
    #                                          asn_to_prefix_count=asn_to_prefix_count)

    global_list = choose_hops_for_ttl_exp_v2(total_requests=total_requests, asn_list=asn_list,
                                             asn_to_prefix_count=asn_to_prefix_count)

    # local_list = choose_hops_for_ttl_exp_v3(total_requests=total_requests, asn_to_cnt_tup=asn_to_cnt_tup,
    #                                         asn_to_address_count=asn_to_address_count)
    print("yo {}".format(len(global_list)))
    with open("global_tuple_list.json".format(LOCAL), "w") as ouf:
        json.dump(global_list, fp=ouf)


def create_lst(ll):
    if LOCAL:
        ans = choose_hops_for_ttl_exp_v2(total_requests=10000)
    else:
        ans = choose_hops_for_ttl_exp_v2(total_requests=ll)
    print(len(ans))
    if LOCAL:
        ans = ans[: 20000]
    with open("ttl_data_set-live-{}.json".format(LOCAL), "w") as ouf:
        json.dump(ans, fp=ouf)


