import json
import logging
from collections import defaultdict

import django

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
            "Proxy Error: No peers available",
            "Bad Port. Ports we support: https://brightdata.com/faq#integration-ports",
            "Proxy Error: socket hang up",
            "Proxy Error: Failed to establish connection with peer",
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
                if response.error in self.proxy_errors:
                    proxy_error_count += 1
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


def get_url_file_name(url):
    url = url[7:]
    url = url.replace("/", "\\")
    return url


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


def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])



