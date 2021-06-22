import json
import logging
from random import randrange

import django

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, get_ocsp_request_headers, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples
from OCSP_DNS_DJANGO.models import *

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

from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder


def luminati_master_crawler():

    logger.info("Starting ocsp job now !")
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]
    # Tune here

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    # 240*214*20*.002333
    for ocsp_url in ocsp_urls_lst:
        ocsp_url_instance = None
        if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
            continue
        else:
            ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)

        q_key = "ocsp:serial:" + ocsp_url
        elements = r.lrange(q_key, 0, -1)

        # Tune here
        elements = elements[0: 20]
        elements = [e.decode() for e in elements]

        for element in elements:
            serial_number = None
            try:
                serial_number, akid, fingerprint = element.split(":")
                ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
                ca_cert = pem.readPemFromString(ca_cert)
                issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

                ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

                ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                          userCert=None, add_nonce=False)

                f = open("OCSP_DNS_DJANGO/countries.json")
                d = json.load(f)
                headers = get_ocsp_request_headers_as_tuples(ocsp_host)

                keys = list(d.keys())
                # Tune here

                for c in range(len(keys)):
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
                        per_cert_dict = {}
                        for header in bb.headers.keys():
                            if header.startswith('x-luminati'):
                                per_cert_dict[header] = bb.headers[header]

                        b = bb.read()
                        decoded_response = return_ocsp_result(b, is_bytes=True)

                        if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
                            ocsp_data_luminati.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                                     fingerprint=fingerprint,
                                                     ocsp_response=b,
                                                     ocsp_response_status=str(decoded_response.response_status),
                                                              country_verbose_name=country_verbose_name, country_code=cc,
                                                              luminati_headers=str(per_cert_dict))
                        else:
                            delegated_responder = False
                            if len(decoded_response.certificates) > 0:
                                delegated_responder = True
                            ocsp_data_luminati.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number,
                                                              akid=akid,
                                                              fingerprint=fingerprint,
                                                              ocsp_response=b,
                                                              ocsp_response_status=str(
                                                                  decoded_response.response_status),
                                                              ocsp_cert_status=decoded_response.certificate_status,
                                                              country_verbose_name=country_verbose_name,
                                                              country_code=cc, delegated_response=delegated_responder,
                                                              luminati_headers=str(per_cert_dict))


                    except Exception as e:
                        if hasattr(e, 'hdrs'):
                            err_msg = str(e) + "\n" + str(e.hdrs)
                        else:
                            err_msg = str(e)

                        ocsp_data_luminati.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number,
                                                          akid=akid,
                                                          fingerprint=fingerprint,
                                                          country_verbose_name=country_verbose_name,
                                                          country_code=cc, has_error=True, error=err_msg)

            except Exception as e:
                logger.error(
                    "Error in init Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url, e))

