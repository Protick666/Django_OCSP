import asyncio
import logging
import random
import time

import aiohttp
import django
import redis
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import get_total_cert_per_ocsp_url, \
    get_ocsp_url_number, choose_hops
from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.tools import fix_cert_indentation
from base64 import b64encode, b64decode


django.setup()

logger = logging.getLogger(__name__)


if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

is_nonce = False

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

id_to_hash = {}

global_ans = []

skid_to_cert = {}

async def query_through_luminati(headers, ocsp_url, ocspReq,
                                 ocsp_url_id, serial_number, akid,
                                 fingerprint, type, session, element, ocspReqconfig, save, element_identifier):
    try:
        import random, string, time
        global config, id_to_hash

        to_store = {}
        to_store['target'] = ocsp_url
        to_store['serial_number'] = serial_number
        to_store['akid'] = akid
        to_store['time-pre'] = time.time()
        to_store['hop'] = element
        to_store['hop_type'] = type
        to_store['mode'] = "{}-{}".format(config.nonce, config.mode)

        if config.nonce:
            a = 1
            ocspReq = makeOcspRequest(issuerCert=ocspReqconfig.issuerCert, userSerialNumber=ocspReqconfig.userSerialNumber,
                                      userCert=None, add_nonce=True)

        # TODO
        # element = '4766'

        letters = string.ascii_lowercase

        session_key = ''.join(random.choice(letters) for i in range(5)) + str(int(time.time()))

        if config.nonce or (not save):

            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(
                element, session_key)
        else:
            prev_hash = id_to_hash[element_identifier]
            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}-ip-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(
                element, session_key, prev_hash)

        to_store['time-start'] = time.time()

        async with session.post(url=ocsp_url,
                                proxy=proxy_url,
                                data=encoder.encode(ocspReq), headers=headers) as response:

            result_data = await response.read()

            to_store['status_code-end'] = response.status
            to_store['time-end'] = time.time()
            headers = response.headers
            headers = dict(headers)
            to_store['headers'] = headers

            if isinstance(result_data, str):
                raise Exception("response-str-{}".format(result_data))
            elif not isinstance(result_data, bytes):
                raise Exception("response-unknown-{}".format(str(result_data)))

            s = ""
            try:
                s = result_data.decode()
            except:
                pass
            if 'No peers' in s:
                raise Exception("no-peers-{}")

            response_b64_encoded = b64encode(result_data).decode("utf-8")
            to_store['response_b64_encoded'] = response_b64_encoded

            # reverse b64decode(response_b64_encoded.encode())

            decoded_response = return_ocsp_result(result_data, is_bytes=True)

            if isinstance(decoded_response, str):
                raise Exception("decode-str-{}:{}".format(decoded_response))

            has_nonce = False

            ocsp_response_status = str(decoded_response.response_status)
            if 'SUCCESSFUL' in ocsp_response_status:
                delegated_response = False
                ocsp_cert_status = str(decoded_response.certificate_status)
                if len(decoded_response.certificates)  > 0:
                    delegated_response = True
                try:

                    for e in list(decoded_response.extensions):
                        if '1.3.6.1.5.5.7.48.1.2' in (str(e.oid)):
                            has_nonce = True
                except:
                    pass

            to_store['has_nonce'] = has_nonce

            to_store['ocsp_response_status'] = ocsp_response_status
            to_store['delegated_response'] = delegated_response
            to_store['ocsp_cert_status'] = ocsp_cert_status



            for header in headers.keys():
                if header.startswith('x-luminati'):
                    if header == 'x-luminati-ip':
                        if not save:
                            id_to_hash[element_identifier] = headers[header]
                        else:
                            a = 1

            to_store['is_normal'] = True
            if save:
                global_ans.append(to_store)
    except Exception as e:
        to_store['is_normal'] = False

        if "TimeoutError" in str(type(e)):
            to_store['error'] = "TimeoutError"
        else:
            to_store['error'] = str(e)

        global_ans.append(to_store)


def process_cert_async(ocsp_host, ocsp_url, ocspReq,
                       ocsp_url_id, serial_number,
                       akid, fingerprint, session,
                       tasks, chosen_hop_list, ocspReqconfig, save):
    try:

        headers = get_ocsp_request_headers_as_tuples(ocsp_host)

        import random

        for hop_tuple in chosen_hop_list:
            element, element_identifier, type = hop_tuple[0], hop_tuple[1], 'ASN'

            task = asyncio.ensure_future(query_through_luminati(headers=headers, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                                                ocsp_url_id=ocsp_url_id,
                                                                serial_number=serial_number,
                                                                akid=akid, fingerprint=fingerprint,
                                                                type=type, session=session, element=element,
                                                                ocspReqconfig=ocspReqconfig, save=save,
                                                                element_identifier=element_identifier))
            tasks.append(task)



    except Exception as e:
        logger.error(
            "Error in asyncio ({})".format(e))


async def process_ocsp_urls_async(ocsp_url_list, ocsp_url_to_id_dict, chosen_hop_list, save):
    timeout = aiohttp.ClientTimeout(total=180)
    global config

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for ocsp_url in ocsp_url_list:

            epoch = int(time.time())
            """
                Choosing prev day
            """
            day_index = ((epoch // (24 * 60 * 60)) % 2 + 1) % 2
            q_key = "{}-{}".format(day_index, ocsp_url)

            elements = r.lrange(q_key, 0, -1)
            elements = [e.decode() for e in elements]
            elements = list(set(elements))

            # if LOCAL:
            #     # TODO fix 2
            #     elements = elements[: 2]

            # if len(elements) > TOTAL_CERTS:
            #     elements = elements[len(elements) - TOTAL_CERTS:]

            for element in elements:
                serial_number = None
                try:
                    # r.lpush(serial_key, "{}:{}:{}".format(serial, finger_print, akid))
                    serial_number_hex_str, fingerprint, akid = element.split(":")

                    if akid.upper() in skid_to_cert:
                        cert_string = skid_to_cert[akid.upper()]
                    else:
                        cert_string = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())



                    ca_cert = pem.readPemFromString(cert_string)



                    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
                    #
                    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

                    serial_integer = int(serial_number_hex_str, 16)

                    ocspReqconfig = OCSPreqConfig()
                    if not config.nonce:
                        ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_integer)),
                                                  userCert=None, add_nonce=False)
                    else:
                        ocspReq = None
                        ocspReqconfig.issuerCert = issuerCert
                        ocspReqconfig.userSerialNumber = hex(int(serial_integer))

                    process_cert_async(ocsp_host, ocsp_url=ocsp_url, ocspReq=ocspReq,
                                       ocsp_url_id="",
                                       serial_number=serial_integer, akid=akid,
                                       fingerprint=fingerprint, session=session, tasks=tasks,
                                       chosen_hop_list=chosen_hop_list,
                                       ocspReqconfig=ocspReqconfig, save=save)

                except Exception as e:
                    print(serial_number, akid)
                    a = 1
                    logger.error(
                        "Error in init Processing cert serial {}, akid {} for ocsp url {} ({})".format(serial_number, akid, ocsp_url,
                                                                                              e))
        execution_results = await asyncio.gather(*tasks)

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans

def luminati_master_non_db(mode, nonce, dump_prefix):

    import json
    global skid_to_cert
    f = open("ski_to_cert.json")
    skid_to_cert = json.load(f)


    nonce_ex = ""
    if nonce:
        nonce_ex = "nonce"
    else:
        nonce_ex = "no-nonce"
    dump_dir = dump_prefix + "{}/{}/".format(nonce, mode)
    from pathlib import Path
    Path(dump_dir).mkdir(parents=True, exist_ok=True)

    global is_nonce
    if mode not in ["get", "post"] or nonce not in [True, False]:
        print("bad parameters")
        return

    """
        Set parameters
    """
    global config
    config.nonce = nonce
    config.mode = mode

    is_nonce = config.nonce

    starting_time = time.time()

    logger.info("Starting ocsp job now !")

    r = get_redis_host()

    """
            Get OCSP urls
    """

    ocsp_urls_set = r.smembers("ocsp_urls")
    TOTAL_OCSP_URLS = get_ocsp_url_number(len(ocsp_urls_set))
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set][: TOTAL_OCSP_URLS]
    # TODO
    # ocsp_urls_lst = ['http://ocsp.globalsign.com/prodrivetechnologiesgccr3ovtlsca2022']
    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    ocsp_url_to_id_dict = {}
    chosen_hop_list = choose_hops()
    # hop_chunks = chunks(chosen_hop_list, 1000)
    # TODO fix 2
    chosen_hop_list = random.sample(chosen_hop_list, 1000)

    logger.info("Chosen total {} hops".format(len(chosen_hop_list)))


    global id_to_hash, global_ans
    for ocsp_url in ocsp_urls_lst:
        try:
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

            import json
            with open("{}{}-{}.json".format(dump_dir, int(time.time()), random.randint(1, 1000000)), "w") as ouf:
                json.dump(global_ans, fp=ouf)

            id_to_hash = {}
            global_ans = []



        except Exception as e:
            id_to_hash = {}
            global_ans = []
        # id_to_hash = {}
        #
        # global_ans = []
        print("Done with {}".format(ocsp_url))



def init(mode, nonce, dump_prefix):
    # (mode="post", nonce=True, dump_prefix='test/')
    while True:
        luminati_master_non_db(mode=mode, nonce=nonce, dump_prefix=dump_prefix)
# luminati_master_crawler_async_v2()


