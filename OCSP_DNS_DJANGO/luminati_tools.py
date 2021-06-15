import json
import logging

import django

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, get_ocsp_request_headers, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples

django.setup()

logger = logging.getLogger(__name__)
import redis
from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST

if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST


r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")

import redis

from OCSP_DNS_DJANGO.tools import fix_cert_indentation

import time

from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder


def ocsp_job_luminati():
    t1 = time.perf_counter()

    logger.info("Starting ocsp job now !")
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    mother_dict = {}

    for ocsp_url in ocsp_urls_lst:

        per_url_dict = {}

        ocsp_url_instance = None
        q_key = "ocsp:serial:" + ocsp_url
        elements = r.lrange(q_key, 0, -1)
        elements = [e.decode() for e in elements]
        elements = elements[0: 5]

        print("Processing ocsp url {}".format(ocsp_url))

        for element in elements:
            per_cert_dict = {}
            serial_number = None
            try:
                serial_number, akid, fingerprint = element.split(":")
                ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
                ca_cert = pem.readPemFromString(ca_cert)
                issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

                ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

                headers = get_ocsp_request_headers(ocsp_host)
                ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)), userCert=None, add_nonce=False)

                import requests as r_req
                response = r_req.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=10)
                decoded_response = return_ocsp_result(response)

                print("Initial: {}".format(decoded_response.response_status))

                per_cert_dict['without_proxy'] = {"response": str(decoded_response.response_status)}

                f = open("OCSP_DNS_DJANGO/countries.json")
                d = json.load(f)
                headers = get_ocsp_request_headers_as_tuples(ocsp_host)

                keys = list(d.keys())

                import random
                chosen_key_indexes = random.sample(range(0, len(keys)), 5)

                for c in chosen_key_indexes:
                    try:
                        country_key = keys[c]
                        country_verbose_name = d[country_key]['country']
                        cc = d[country_key]["cc"]

                        import urllib.request
                        opener = urllib.request.build_opener(
                            urllib.request.ProxyHandler(
                                {
                                    'http': 'http://lum-customer-c_9c799542-zone-residential-country-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(
                                        cc),
                                    'https': 'http://lum-customer-c_9c799542-zone-residential-country-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(
                                        cc)}))
                        opener.addheaders = headers
                        bb = opener.open(ocsp_url, data=encoder.encode(ocspReq))
                        per_cert_dict[country_verbose_name] = {}
                        for header in bb.headers.keys():
                            if header.startswith('x-luminati'):
                                per_cert_dict[country_verbose_name][header] = bb.headers[header]

                        b = bb.read()
                        decoded_response = return_ocsp_result(b, is_bytes=True)
                        per_cert_dict[country_verbose_name]["response"] = str(decoded_response.response_status)

                        print("Secondary: for country {}: {}".format(country_verbose_name,
                                                                     decoded_response.response_status))
                    except Exception as e:
                        if hasattr(e, 'hdrs'):
                            err_msg = str(e.hdrs)
                        else:
                            err_msg = str(e)
                        if country_verbose_name not in per_cert_dict:
                            per_cert_dict[country_verbose_name] = {}
                        per_cert_dict[country_verbose_name]["error"] = err_msg

            except Exception as e:
                logger.error("Error in init Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url, e))

            per_url_dict[serial_number] = per_cert_dict

        mother_dict[ocsp_url] = per_url_dict

    with open("ocsp_luminati.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf, sort_keys=True, indent=2)