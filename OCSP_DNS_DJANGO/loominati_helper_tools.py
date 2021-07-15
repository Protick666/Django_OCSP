from OCSP_DNS_DJANGO.local import LOCAL
import json
import random
from OCSP_DNS_DJANGO.models import ASN,CN

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
    f = open('luminati_country_to_asn.json')
    country_to_asn_list = json.load(f)

    chosen_asn_outer = []
    for country in country_to_asn_list:
        asn_list = country_to_asn_list[country]
        total_available_asn = len(asn_list)
        allowed_asn_number = choose_asn_number_per_country(total_available_asn)
        chosen_asn_s = random.sample(asn_list, allowed_asn_number)
        chosen_asn_s = [(element[0], country) for element in chosen_asn_s]
        chosen_asn_outer = chosen_asn_outer + chosen_asn_s

    if LOCAL:
        chosen_asn_outer = chosen_asn_outer[0: 10]
    return chosen_asn_outer


def choose_hops():
    # 17844
    dash_board_asns = choose_candidate_asns()
    dash_board_asns = [element[0] for element in dash_board_asns]
    if LOCAL:
        dash_board_split = 10
    else:
        dash_board_split = 50

    dash_board_asns = random.sample(dash_board_asns, dash_board_split)

    f = open('OCSP_DNS_DJANGO/luminati_data/successful_asns.json')
    if LOCAL:
        global_asn_split = 10
    else:
        global_asn_split = 100
    asn_list = json.load(f)
    asn_list = random.sample(asn_list, dash_board_split)

    all_asns = dash_board_asns + asn_list
    all_asns = [(element, ASN) for element in all_asns]


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





