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
    get_ocsp_url_number, choose_hops
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

class Config:
    """
        get/post
    """
    mode = None
    """
            true/false
    """
    nonce = None

class OCSPreqConfig:
    issuerCert = None
    userSerialNumber = None

config = Config()
def get_redis_host():
    r = redis.Redis(host=redis_host, port=6379, db=4, password="certificatesarealwaysmisissued")
    return r

r = get_redis_host()

TOTAL_CERTS = get_total_cert_per_ocsp_url()


async def query_through_luminati(headers, ocsp_url, ocspReq,
                                 ocsp_url_id, serial_number, akid,
                                 fingerprint, type, session, element, ocspReqconfig, save):
    try:
        global config

        if config.nonce:
            ocspReq = makeOcspRequest(issuerCert=ocspReqconfig.issuerCert, userSerialNumber=ocspReqconfig.userSerialNumber,
                                      userCert=None, add_nonce=True)


        import random, string, time
        letters = string.ascii_lowercase

        # TODO make the session keys precalculated
        session_key = ''.join(random.choice(letters) for i in range(5)) + str(int(time.time()))

        if type == ASN:
            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(element, session_key)
        elif type == CN:
            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-country-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(element, session_key)


        end_node_meta_data = ""

        async with session.post(url=ocsp_url,
                                proxy=proxy_url,
                                data=encoder.encode(ocspReq), headers=headers) as response:

            result_data = await response.read()
            headers = response.headers
            decoded_response = return_ocsp_result(result_data, is_bytes=True)

            if isinstance(decoded_response, str) and isinstance(result_data, bytes):
                raise Exception(result_data.decode())

            per_cert_dict = {}
            for header in headers.keys():
                if header.startswith('x-luminati'):
                    per_cert_dict[header] = headers[header]

    except Exception as e:
        a = 1
        # await store_error_msg_of_ocsp_response(e=e, ocsp_url_id=ocsp_url_id, serial_number=serial_number,
        #                                        akid=akid, fingerprint=fingerprint,
        #                                        type=type, element=element, end_node_meta_data=end_node_meta_data)


def process_cert_async(ocsp_host, ocsp_url, ocspReq,
                       ocsp_url_id, serial_number,
                       akid, fingerprint, session,
                       tasks, chosen_hop_list, ocspReqconfig, save):
    try:

        headers = get_ocsp_request_headers_as_tuples(ocsp_host)

        import random

        for hop_tuple in chosen_hop_list:
            # TODO asn, cnt alada koro
            element, type = hop_tuple[0], 'ASN'

            task = asyncio.ensure_future(query_through_luminati(headers=headers, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                                                ocsp_url_id=ocsp_url_id,
                                                                serial_number=serial_number,
                                                                akid=akid, fingerprint=fingerprint,
                                                                type=type, session=session, element=element, ocspReqconfig=ocspReqconfig, save=save))
            tasks.append(task)



    except Exception as e:
        logger.error(
            "Error in asyncio ({})".format(e))


async def process_ocsp_urls_async(ocsp_url_list, ocsp_url_to_id_dict, chosen_hop_list, save):
    timeout = aiohttp.ClientTimeout(total=120)
    global config

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for ocsp_url in ocsp_url_list:
            # ocsp_url_id = ocsp_url_to_id_dict[ocsp_url]

            epoch = int(time.time())
            """
                Choosing prev day
            """
            day_index = ((epoch // (24 * 60 * 60)) % 2 + 1) % 2
            q_key = "{}-{}".format(day_index, ocsp_url)

            elements = r.lrange(q_key, 0, -1)
            elements = [e.decode() for e in elements]
            elements = list(set(elements))

            if LOCAL:
                elements = elements[: 10]

            # if len(elements) > TOTAL_CERTS:
            #     elements = elements[len(elements) - TOTAL_CERTS:]

            for element in elements:
                serial_number = None
                try:
                    # TODO see capitalization
                    serial_number, akid, fingerprint = element.split(":")

                    ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
                    ca_cert = pem.readPemFromString(ca_cert)
                    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())


                    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

                    ocspReqconfig = OCSPreqConfig()
                    if not config.nonce:
                        ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                                  userCert=None, add_nonce=False)
                    else:
                        ocspReq = None
                        ocspReqconfig.issuerCert = issuerCert
                        ocspReqconfig.userSerialNumber = hex(int(serial_number))

                    process_cert_async(ocsp_host, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                       ocsp_url_id="",
                                       serial_number=serial_number, akid=akid,
                                       fingerprint=fingerprint, session=session, tasks=tasks,
                                       chosen_hop_list=chosen_hop_list, ocspReqconfig=ocspReqconfig, save=save)

                except Exception as e:
                    logger.error(
                        "Error in init Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url,
                                                                                              e))
        execution_results = await asyncio.gather(*tasks)


def luminati_master_non_db(mode, nonce):
    if mode not in ["get", "post"] or nonce not in [True, False]:
        print("bad parameters")
        return

    """
        Set parameters
    """
    global config
    config.nonce = nonce
    config.mode = mode
    starting_time = time.time()

    logger.info("Starting ocsp job now !")

    r = get_redis_host()

    """
            Get OCSP urls
    """

    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    TOTAL_OCSP_URLS = get_ocsp_url_number(len(ocsp_urls_set))
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set][: TOTAL_OCSP_URLS]

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    ocsp_url_to_id_dict = {}

    # TODO major TODO
    chosen_hop_list = choose_hops()

    logger.info("Chosen total {} hops".format(len(chosen_hop_list)))

    for ocsp_url in ocsp_urls_lst:
        if config.nonce:
            asyncio.run(process_ocsp_urls_async(ocsp_url_list=[ocsp_url],
                                                ocsp_url_to_id_dict=ocsp_url_to_id_dict,
                                                chosen_hop_list=chosen_hop_list, save=True))
        else:
            for i in range(2):
                asyncio.run(process_ocsp_urls_async(ocsp_url_list=[ocsp_url],
                                                    ocsp_url_to_id_dict=ocsp_url_to_id_dict,
                                                    chosen_hop_list=chosen_hop_list, save=False))

            asyncio.run(process_ocsp_urls_async(ocsp_url_list=[ocsp_url],
                                                ocsp_url_to_id_dict=ocsp_url_to_id_dict,
                                                chosen_hop_list=chosen_hop_list, save=True))

    elapsed_time = time.time() - starting_time
    print("Elapsed time {}".format(elapsed_time))

# luminati_master_crawler_async_v2()


