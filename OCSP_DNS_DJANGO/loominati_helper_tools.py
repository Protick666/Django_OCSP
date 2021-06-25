from OCSP_DNS_DJANGO.local import LOCAL
import json
import random

def choose_asn_number_per_country(number):
    if LOCAL:
        return min(number, 2)
    else:
        return max(int(number * .2), 1)


def get_total_cert_per_ocsp_url():
    if LOCAL:
        return 2
    else:
        return 20

def choose_candidate_asns():
    f = open('luminati_data/luminati_country_to_asn.json')
    country_to_asn_list = json.load(f)

    chosen_asn_outer = []
    for country in country_to_asn_list:
        asn_list = country_to_asn_list[country]
        total_available_asn = len(asn_list)
        allowed_asn_number = choose_asn_number_per_country(total_available_asn)
        chosen_asn_s = random.sample(asn_list, allowed_asn_number)
        chosen_asn_s = [(element[0], country) for element in chosen_asn_s]
        chosen_asn_outer = chosen_asn_outer + chosen_asn_s

    return chosen_asn_outer


def get_ocsp_url_number(total_number):
    if LOCAL:
        return 2
    else:
        return total_number





