from OCSP_DNS_DJANGO.local import LOCAL
import json
import random
from OCSP_DNS_DJANGO.models import *


def get_ocsp_hosts():
    # TODO test
    ocsp_hosts = ocsp_url_db.objects.all()
    return [e.url for e in ocsp_hosts]


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
    f = open('lum_dash_asns_list.json')
    asn_list = json.load(f)
    asn_cn_tuple_list = [(e, "N/A") for e in asn_list]
    return asn_cn_tuple_list
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
    dash_board_asns = choose_candidate_asns()
    dash_board_asns = [element[0] for element in dash_board_asns]
    if LOCAL:
        dash_board_split = 10
    else:
        dash_board_split = 150

    dash_board_asns = random.sample(dash_board_asns, dash_board_split)

    ## TODO masssive: rebuild this json after scanning
    # f = open('OCSP_DNS_DJANGO/luminati_data/successful_asns.json')
    # if LOCAL:
    #     global_asn_split = 10
    # else:
    #     global_asn_split = 800
    # asn_list = json.load(f)
    # asn_list = random.sample(asn_list, global_asn_split)
    asn_list = []
    all_asns = dash_board_asns + asn_list
    all_asns = [(element, ASN) for element in all_asns]

    if only_asns:
        return all_asns


    f = open("OCSP_DNS_DJANGO/countries.json")
    d = json.load(f)
    country_codes = []
    for e in d:
        country_codes.append(d[e]["cc"])
    if LOCAL:
        country_split = 10
    else:
        country_split = 50
    country_codes = random.sample(country_codes, country_split)
    all_countries = [(element, CN) for element in country_codes]

    return all_asns + all_countries


def get_ocsp_url_number(total_number):
    if LOCAL:
        return 10
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
    for line in open('asns_full_info.json', 'r'):
        tweets.append(json.loads(line))

    total_prefixes = 0
    for a in tweets:
        total_prefixes += a['announcing']['numberPrefixes']

    for a in tweets:
        asn_list.add(a['asn'])
        asn_to_prefix_count[a['asn']] = a['announcing']['numberPrefixes']

    asn_to_prefix_count['all'] = total_prefixes

    return list(asn_list), asn_to_prefix_count


def choose_hops_for_ttl_exp_v2(total_requests, asn_list, asn_to_prefix_count):
    lst = []

    for asn in asn_list:
        if asn not in asn_to_prefix_count:
            print(asn)
            continue
        if asn_to_prefix_count[asn] == 0:
            continue
        allotment = (asn_to_prefix_count[asn] / asn_to_prefix_count['all']) * total_requests
        allotment = max(min(allotment, 5), 100)
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


def create_lst_both(total_requests):
    asn_list, asn_to_prefix_count = get_all_asn_list_with_prefix_count()

    f = open("global_asn_list_updated.json")
    local_asn_list = json.load(f)

    print("Local ", len(local_asn_list))
    print("Global ", len(asn_list))

    global_list = choose_hops_for_ttl_exp_v2(total_requests=total_requests, asn_list=asn_list,
                                             asn_to_prefix_count=asn_to_prefix_count)

    local_list = choose_hops_for_ttl_exp_v2(total_requests=total_requests * 2, asn_list=local_asn_list,
                                             asn_to_prefix_count=asn_to_prefix_count)


    print("Global ", len(global_list))
    print("Local ", len(local_list))
    with open("ttl_data_set-live-global-{}.json".format(LOCAL), "w") as ouf:
        json.dump(global_list, fp=ouf)
    with open("ttl_data_set-live-local-{}.json".format(LOCAL), "w") as ouf:
        json.dump(local_list, fp=ouf)


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


