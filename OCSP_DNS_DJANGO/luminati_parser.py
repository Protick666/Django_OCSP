import json
import logging
from collections import defaultdict

import django

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host
from OCSP_DNS_DJANGO.models import *

django.setup()

logger = logging.getLogger(__name__)


class LuminatiModelManager:
    def __init__(self):
        self.response_enum = ["OCSPResponseStatus.SUCCESSFUL",
                              "OCSPResponseStatus.UNAUTHORIZED",
                              "OCSPResponseStatus.MALFORMED_REQUEST",
                              "OCSPResponseStatus.INTERNAL_ERROR",
                              "OCSPResponseStatus.TRY_LATER"]

        self.cert_status_enum = ["OCSPCertStatus.GOOD",
                                 "OCSPCertStatus.REVOKED",
                                 "OCSPCertStatus.UNKNOWN"]

        self.proxy_errors = [
            "Proxy Error",
            "Bad Port"
        ]

    # TODO read from db
    @staticmethod
    def get_responder_count_stat(sorted_wrt_count=True):
        f = open('ocsp.json')
        d = json.load(f)
        return d

    def find_response_time(self, s):
        f_index = s.find("response")
        f_index = f_index + 9
        e_index = s[f_index:].find(",")
        return int(s[f_index: f_index + e_index])

    @staticmethod
    def get_responders():
        return ocsp_url_db.objects.all()

    def is_proxy_error(self, error):
        for e in self.proxy_errors:
            if e in error:
                return True
        return False

    def get_responder_data(self, responder):
        ocsp_responses = OcspResponsesWrtAsn.objects.filter(ocsp_url=responder)
        total, error_count, proxy_error_count, timeout_count = ocsp_responses.count(), 0, 0, 0
        response_dict = defaultdict(lambda: 0)
        response_cert_status_dict = defaultdict(lambda: 0)
        responder_to_asn_data = defaultdict(lambda : list())
        responder_to_asn_timeout_freq = defaultdict(lambda: 0)

        for response in ocsp_responses:
            if response.has_error:
                error_count += 1
                if response.error == 'TimeoutError':
                    timeout_count += 1
                    if response.mode == 'ASN':
                        responder_to_asn_timeout_freq[response.hop] += 1
                if self.is_proxy_error(response.error):
                    proxy_error_count += 1
                # if response.error in self.proxy_errors:
                #     proxy_error_count += 1
            else:
                response_dict[response.ocsp_response_status] += 1
                responder_to_asn_data[response.hop].append(self.find_response_time(response.luminati_headers))
                if response.ocsp_response_status == 'OCSPResponseStatus.SUCCESSFUL':
                    response_cert_status_dict[response.ocsp_cert_status] += 1


        return {
            "total_records": total,
            "error_count": error_count,
            "proxy_error_count": proxy_error_count,
            "timeout_count": timeout_count,
            "response_type_count": response_dict,
            "responder_to_asn_data": responder_to_asn_data,
            "responder_to_asn_timeout_freq": responder_to_asn_timeout_freq,
            "response_cert_status_dict": response_cert_status_dict
        }

    def error_weird_cases(self, responder):
        ocsp_responses = OcspResponsesWrtAsn.objects.filter(ocsp_url=responder)

        asn_to_error = {}

        for response in ocsp_responses:
            if response.mode != 'ASN':
                continue
            if response.has_error:
                if response.error == 'TimeoutError' or self.is_proxy_error(response.error):
                    pass
                else:
                    if response.hop not in asn_to_error:
                        asn_to_error[response.hop] = {"count": 0}
                    asn_to_error[response.hop]['error'] = True
                    asn_to_error[response.hop]['count'] = asn_to_error[response.hop]['count'] + 1
            else:
                if response.hop not in asn_to_error:
                    asn_to_error[response.hop] = {"count": 0}
                asn_to_error[response.hop]['no_error'] = True
                asn_to_error[response.hop]['count'] = asn_to_error[response.hop]['count'] + 1

        return asn_to_error

    def one_cert_info(self, responder):
        local_lst = []
        ocsp_responses = OcspResponsesWrtAsn.objects.filter(ocsp_url=responder,
                                                            ocsp_response_status='OCSPResponseStatus.SUCCESSFUL',
                                                            ).order_by('-id')[:5]

        for response in ocsp_responses:
            nested_dict = {}
            nested_dict["serial"] = response.serial
            nested_dict["akid"] = response.akid
            nested_dict["fingerprint"] = response.fingerprint
            local_lst.append(nested_dict)

        return local_lst





def get_url_file_name(url):
    url = url[7:]
    url = url.replace("/", "-")
    return url


def luminati_parser_error():
    from pathlib import Path

    Path('luminati_error_case/').mkdir(parents=True, exist_ok=True)
    luminati_model_manager = LuminatiModelManager()

    # responders_count_stat = luminati_model_manager.get_responder_count_stat()
    all_responders = LuminatiModelManager.get_responders()
    mother_dict = {}
    for responder in all_responders:
        try:
            relevant_data = luminati_model_manager.error_weird_cases(responder=responder)
            mother_dict[responder.url] = relevant_data

            url_file_name = get_url_file_name(responder.url)

            with open("luminati_error_case/{}.json".format(url_file_name), "w") as ouf:
                json.dump(relevant_data, fp=ouf)
            print("Done with processing {}".format(responder.url))

        except Exception as e:
            print("Exception when processing {}, {}".format(responder.url, e))

    with open("luminati_error_case/all_data.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)


def luminati_parser():
    from pathlib import Path

    Path('luminati_stats/').mkdir(parents=True, exist_ok=True)
    luminati_model_manager = LuminatiModelManager()

    #responders_count_stat = luminati_model_manager.get_responder_count_stat()
    all_responders = LuminatiModelManager.get_responders()

    mother_dict = {}
    for responder in all_responders:
        try:
            relevant_data = luminati_model_manager.get_responder_data(responder=responder)
            mother_dict[responder.url] = relevant_data

            url_file_name = get_url_file_name(responder.url)

            with open("luminati_stats/{}.json".format(url_file_name), "w") as ouf:
                json.dump(relevant_data, fp=ouf)
            print("Done with processing {}".format(responder.url))

        except Exception as e:
            print("Exception when processing {}, {}".format(responder.url, e))

    with open("luminati_stats/all_data.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)


def get_stat_file():
    f = open('luminati_stats/all_data.json')
    d = json.load(f)
    return d


def get_objective_rate(objective_str, count=10):
    candidate_c = 0
    data = get_stat_file()
    objective_perc = {}
    for key in data:
        #print("pre", key)
        total_records = data[key]['total_records']
        objective_count = data[key][objective_str]
        if objective_count > 0:
            candidate_c += 1
        proxy_error_count = data[key]['proxy_error_count']
        if total_records - proxy_error_count == 0:
            continue
        # TODO only error calculation e objective_count - proxy_error_count hobe in first term
        objective_perc[key] = (objective_count) / (total_records - proxy_error_count)
        #print((objective_count), (total_records - proxy_error_count), (objective_count - proxy_error_count) / (total_records - proxy_error_count))
        #print("post", key)

    objective_perc = dict(sorted(objective_perc.items(), key=lambda item: item[1]))

    with open("luminati_stats/{}_rate.json".format(objective_str), "w") as ouf:
        json.dump(objective_perc, fp=ouf)

    for e in reversed(list(objective_perc.items())[-count:]):
        print(e[0], "       ", e[1])
    print("Total candidates", candidate_c)

import numpy as np

import statistics
def get_latency_dist():
    data = get_stat_file()
    m_dict = {}
    for key in data:

        median_latency = []
        candidate = 0
        for asn in data[key]['responder_to_asn_data']:
            if len(data[key]['responder_to_asn_data'][asn]) < 10:
                continue
            candidate += 1
            median_latency.append((asn, statistics.median(data[key]['responder_to_asn_data'][asn])))

        if candidate < 5:
            continue
        m_dict[key] = {}

        m_dict[key]['variance'] = np.var([e[1] for e in median_latency])
        m_dict[key]['max_latency'] = max([e[1] for e in median_latency])
        m_dict[key]['min_latency'] = min([e[1] for e in median_latency])
        m_dict[key]['max_latency_asn'] = [e[0] for e in median_latency if e[1] ==  m_dict[key]['max_latency']][0]
        m_dict[key]['min_latency_asn'] = [e[0] for e in median_latency if e[1] == m_dict[key]['min_latency']][0]

    m_dict = dict(sorted(m_dict.items(), key=lambda item: item[1]['variance']))

    print("Low variance")
    for e in list(m_dict.items())[0: 5]:
        print(e[0], e[1])


    print("High variance")
    for e in list(m_dict.items())[-5: ]:
        print(e[0], e[1])


def get_compact_info():
    luminati_model_manager = LuminatiModelManager()
    # responders_count_stat = luminati_model_manager.get_responder_count_stat()
    all_responders = LuminatiModelManager.get_responders()
    mother_dict = {}

    is_host_visited = {}

    index = 0
    for responder in all_responders:

        try:
            host = get_ocsp_host(responder.url)
            if host in is_host_visited:
                continue
            is_host_visited[host] = 1
            relevant_data = luminati_model_manager.one_cert_info(responder=responder)
            mother_dict[responder.url] = relevant_data
            index += 1
            if index == 10:
                break

        except Exception as e:
            print("Exception when processing {}, {}".format(responder.url, e))

    with open("compact_info.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)



def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])



