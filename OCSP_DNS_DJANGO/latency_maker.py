from OCSP_DNS_DJANGO.management.commands.scheduler import return_ocsp_result
from OCSP_DNS_DJANGO.models import OcspResponsesWrtAsn, ocsp_data_luminati, ocsp_url_db

from collections import defaultdict


def find_response_time(s):
    f_index = s.find("response")
    f_index = f_index + 9
    e_index = s[f_index:].find(",")
    return int(s[f_index: f_index + e_index])

from collections import defaultdict

def calculate_latency(per_url_general_dict, per_url_per_asn_dict):
    per_url_min_latency, per_url_max_latency, per_url_average_latency = {}, {}, {}
    for url in per_url_per_asn_dict:
        total, total_latency = 0, 0
        for asn in per_url_per_asn_dict[url]:
            latency_list = per_url_per_asn_dict[url][asn]
            for latency in latency_list:
                total += 1
                total_latency += latency

                if url not in per_url_min_latency:
                    per_url_min_latency[url] = (latency, asn)
                elif per_url_min_latency[url][0] > latency:
                    per_url_min_latency[url] = (latency, asn)

                if url not in per_url_max_latency:
                    per_url_max_latency[url] = (latency, asn)
                elif per_url_max_latency[url][0] < latency:
                    per_url_max_latency[url] = (latency, asn)

        per_url_average_latency[url] = total_latency / total

    answer_dict = {}
    for url in per_url_per_asn_dict:
        nested_dict = {}
        nested_dict['average'] = per_url_average_latency[url]
        nested_dict['min_latency'] = (per_url_min_latency[url][0], "ASN: {}".format(per_url_min_latency[url][1]))
        nested_dict['max_latency'] = (per_url_max_latency[url][0], "ASN: {}".format(per_url_max_latency[url][1]))

        answer_dict[url] = nested_dict

    return answer_dict



def find_latency():
    hosts = ocsp_url_db.objects.all()

    per_url_general_dict = defaultdict(lambda: list())
    per_url_per_asn_dict = defaultdict(lambda: defaultdict(lambda: list()))

    for ocsp_host in hosts:
        ocsp_responses_wrt_asns = OcspResponsesWrtAsn.objects.filter(ocsp_url=ocsp_host,
                                                                     ocsp_response_status="OCSPResponseStatus.SUCCESSFUL")

        for response in ocsp_responses_wrt_asns:
            lum_headers = response.luminati_headers
            asn = response.asn
            res_time = find_response_time(lum_headers)
            per_url_general_dict[ocsp_host.url].append(res_time)
            per_url_per_asn_dict[ocsp_host.url][asn].append(res_time)

    latency_results = calculate_latency(per_url_general_dict, per_url_per_asn_dict)

    latency_results = dict(sorted(latency_results.items(), key=lambda x: x[1]['average']))

    import json
    with open("latency_results.json", "w") as ouf:
        json.dump(latency_results, fp=ouf)
