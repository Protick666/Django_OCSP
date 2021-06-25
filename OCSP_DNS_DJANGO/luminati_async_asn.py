import asyncio
import json
import logging
import time

import aiohttp
import django
import redis
from asgiref.sync import sync_to_async
from channels.db import database_sync_to_async
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import choose_candidate_asns, get_total_cert_per_ocsp_url, \
    get_ocsp_url_number
from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples
from OCSP_DNS_DJANGO.models import *
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.tools import fix_cert_indentation, get_dns_records

django.setup()

logger = logging.getLogger(__name__)


if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")

# https://bgp.potaroo.net/cidr/autnums.html
# https://en.wikipedia.org/wiki/ISO_3166-2


TOTAL_CERTS = get_total_cert_per_ocsp_url()

# 612 ASNs
# 109 countries


async def query_through_luminati(headers, ocsp_url, ocspReq,
                                 ocsp_url_id, serial_number, akid,
                                 fingerprint, country_code, session, asn):
    try:

        st = time.time()
        async with session.post(url=ocsp_url,
                                proxy='http://lum-customer-c_9c799542-zone-residential-asn-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(
                                    asn),
                                data=encoder.encode(ocspReq), headers=headers) as response:

            result_data = await response.read()
            headers = response.headers
            decoded_response = return_ocsp_result(result_data, is_bytes=True)
            if type(decoded_response) == type('xxx'):
                raise Exception(decoded_response)
            # print(decoded_response.response_status)

            per_cert_dict = {}
            for header in headers.keys():
                if header.startswith('x-luminati'):
                    per_cert_dict[header] = headers[header]

            await store_ocsp_response(decoded_response=decoded_response, ocsp_url_id=ocsp_url_id,
                                      serial_number=serial_number,
                                      akid=akid, fingerprint=fingerprint,
                                      country_code=country_code,
                                      per_cert_dict=per_cert_dict, b_ocsp_response=result_data, asn=asn)

    except Exception as e:
        await store_error_msg_of_ocsp_response(e=e, ocsp_url_id=ocsp_url_id, serial_number=serial_number,
                                               akid=akid, fingerprint=fingerprint,
                                               country_code=country_code, asn=asn)


@sync_to_async
def store_error_msg_of_ocsp_response(e, ocsp_url_id, serial_number, akid,
                                     fingerprint,
                                     country_code, asn):
    if hasattr(e, 'hdrs'):
        err_msg = str(e) + "\n" + str(e.hdrs)
    else:
        err_msg = str(e)

    print("yo")
    OcspResponsesWrtAsn.objects.create(ocsp_url_id=ocsp_url_id, serial=serial_number,
                                      akid=akid,
                                      fingerprint=fingerprint,
                                      asn=asn,
                                      country_code=country_code, has_error=True, error=err_msg)


@sync_to_async
def store_ocsp_response(decoded_response, ocsp_url_id, serial_number, akid,
                        fingerprint, country_code,
                        per_cert_dict, b_ocsp_response, asn):
    print("yo")
    if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
        OcspResponsesWrtAsn.objects.create(ocsp_url_id=ocsp_url_id, serial=serial_number,
                                          akid=akid,
                                          fingerprint=fingerprint,
                                          ocsp_response=b_ocsp_response,
                                          ocsp_response_status=str(
                                              decoded_response.response_status),
                                          asn=asn,
                                          country_code=country_code,
                                          luminati_headers=str(per_cert_dict))
    else:
        delegated_responder = False
        if len(decoded_response.certificates) > 0:
            delegated_responder = True
        OcspResponsesWrtAsn.objects.create(ocsp_url_id=ocsp_url_id, serial=serial_number,
                                          akid=akid,
                                          fingerprint=fingerprint,
                                          ocsp_response=b_ocsp_response,
                                          ocsp_response_status=str(
                                              decoded_response.response_status),
                                          ocsp_cert_status=decoded_response.certificate_status,
                                          asn=asn,
                                          country_code=country_code, delegated_response=delegated_responder,
                                          luminati_headers=str(per_cert_dict))


def process_cert_async(ocsp_host, ocsp_url, ocspReq,
                       ocsp_url_id, serial_number,
                       akid, fingerprint, session,
                       tasks, chosen_asn_list):
    try:

        headers = get_ocsp_request_headers_as_tuples(ocsp_host)

        import random

        for asn_tuple in chosen_asn_list:
            asn, country_code = asn_tuple[0], asn_tuple[1]

            task = asyncio.ensure_future(query_through_luminati(headers=headers, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                                                ocsp_url_id=ocsp_url_id,
                                                                serial_number=serial_number,
                                                                akid=akid, fingerprint=fingerprint,
                                                                country_code=country_code, session=session, asn=asn))
            tasks.append(task)



    except Exception as e:
        logger.error(
            "Error in asyncio ({})".format(e))


async def process_ocsp_urls_async(ocsp_url_list, ocsp_url_to_id_dict, chosen_asn_list):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for ocsp_url in ocsp_url_list:
            ocsp_url_id = ocsp_url_to_id_dict[ocsp_url]
            q_key = "ocsp:serial:" + ocsp_url
            elements = r.lrange(q_key, 0, -1)

            # Tune here
            elements = elements[0: TOTAL_CERTS]
            elements = [e.decode() for e in elements]

            for element in elements:
                serial_number = None
                try:
                    serial_number, akid, fingerprint = element.split(":")

                    serial_exists = await database_sync_to_async(
                        ocsp_data_luminati.objects.filter(ocsp_url_id=ocsp_url_id, serial=serial_number).exists)()
                    if serial_exists:
                        continue

                    '''
                        MAKE OCSP REQUEST
                    '''
                    ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
                    ca_cert = pem.readPemFromString(ca_cert)
                    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
                    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
                    ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                              userCert=None, add_nonce=False)

                    process_cert_async(ocsp_host, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                       ocsp_url_id=ocsp_url_id,
                                       serial_number=serial_number, akid=akid,
                                       fingerprint=fingerprint, session=session, tasks=tasks,
                                       chosen_asn_list=chosen_asn_list)


                except Exception as e:
                    logger.error(
                        "Error in init Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url,
                                                                                              e))

        execution_results = await asyncio.gather(*tasks)


def luminati_master_crawler_async():
    starting_time = time.time()

    logger.info("Starting ocsp job now !")
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    TOTAL_OCSP_URLS = get_ocsp_url_number(len(ocsp_urls_set))
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set][0: TOTAL_OCSP_URLS]

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    # 240*214*20*.002333
    url_count = 0
    ocsp_url_to_id_dict = {}

    chosen_asn_list = choose_candidate_asns()

    for ocsp_url in ocsp_urls_lst:
        ocsp_url_instance = None
        if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
            ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
            dns_records = get_dns_records(ocsp_url)
            for record in dns_records:
                dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
        else:
            ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)

        ocsp_url_to_id_dict[ocsp_url] = ocsp_url_instance.id

    asyncio.run(process_ocsp_urls_async(ocsp_url_list=ocsp_urls_lst,
                                        ocsp_url_to_id_dict=ocsp_url_to_id_dict,
                                        chosen_asn_list=chosen_asn_list))

    print("Elapsed time {}".format(time.time() - starting_time))
