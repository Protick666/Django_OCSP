import json
import logging

import django
import requests

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples, get_ocsp_request_headers
from OCSP_DNS_DJANGO.models import OcspResponsesWrtAsn
from random import randint
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

from OCSP_DNS_DJANGO.tools import fix_cert_indentation, get_dns_records

from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder


def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


def make_ocsp_query(serial_number, akid, r, ocsp_url, ip_host):
    response = None
    ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
    ca_cert = pem.readPemFromString(ca_cert)
    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
    ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                              userCert=None, add_nonce=False)
    headers = get_ocsp_request_headers(ocsp_host)

    try:
        response = requests.post(ip_host, data=encoder.encode(ocspReq), headers=headers)
        decoded_response = return_ocsp_result(response.content, is_bytes=True)
        d = {}
        d['response_status'] = str(decoded_response.response_status)
        if str(decoded_response.response_status) == "OCSPResponseStatus.SUCCESSFUL":
            d['cert_status'] = str(decoded_response.certificate_status)
        d['elapsed_time'] = response.elapsed.total_seconds()
        return d

    except Exception as e:
        d = {}
        d['error'] = e
        if response:
            d['elapsed_time'] = response.elapsed.total_seconds()
        return d

def get_ips_of_urls():
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]

    from collections import defaultdict
    d = defaultdict(lambda: list())

    for url in ocsp_urls_lst:
        records = get_dns_records(url)
        a_records = [e[1] for e in records if e[0] == 'A_RECORD']
        for a_record in a_records:
            d[url].append(a_record)

    with open("url_to_ips.json", "w") as ouf:
        json.dump(d, fp=ouf, indent=2)


def luminati_master_crawler_cloudflare_cache():
    logger.info("Starting ocsp job now !")

    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")

    ocsp_url = 'http://ocsp2.globalsign.com/gsdomainvalsha2g3'
    ip_host = 'http://104.18.21.226/gsdomainvalsha2g3'
    OCSP_URL_ID = 110

    old_list = []
    new_list = []

    random_list = []
    master_akid = '3D808279C54882A3C312EEDF990F5735489ED0CB'

    ex_serial = '10028015818766309226464494355'

    old_list = OcspResponsesWrtAsn.objects.filter(ocsp_url_id=OCSP_URL_ID,
                                                       ocsp_response_status='OCSPResponseStatus.SUCCESSFUL',
                                                       ocsp_cert_status='OCSPCertStatus.GOOD')[20: 25]
    import random
    # old_list = random.sample(old_list, 5)




    q_key = "ocsp:serial:" + ocsp_url
    elements = r.lrange(q_key, 0, -1)
    elements = [e.decode() for e in elements]
    elements = list(set(elements))[0: 100]
    elements = random.sample(elements, 5)
    new_list = elements

    for i in range(5):
        random_list.append(random_with_N_digits(len(ex_serial)))

    from collections import defaultdict
    ans = defaultdict(lambda: dict())
    import time

    d = {}
    for e in old_list:
        d_d = {}
        for c in range(10):
            data = make_ocsp_query(serial_number=e.serial, akid=e.akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            time.sleep(60)
            d_d[c] = data
        d[e.serial] = d_d
    ans['old'] = d

    d = {}
    for element in new_list:
        d_d = {}
        serial_number, akid, fingerprint = element.split(":")
        for c in range(10):
            data = make_ocsp_query(serial_number=serial_number, akid=akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            time.sleep(60)
            d_d[c] = data
        d[serial_number] = d_d
    ans['new'] = d

    d = {}
    for e in random_list:
        d_d = {}
        for c in range(10):
            data = make_ocsp_query(serial_number=e, akid=master_akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            time.sleep(60)
            d_d[c] = data
        d[e] = d_d
    ans['random'] = d

    with open("cache_exp.json", "w") as ouf:
        json.dump(ans, fp=ouf, indent=2)


def luminati_master_crawler_cloudflare_cache_v2():
    logger.info("Starting ocsp job now !")

    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")

    ocsp_url = 'http://ocsp2.globalsign.com/gsdomainvalsha2g3'
    ip_host = 'http://104.18.21.226/gsdomainvalsha2g3'
    OCSP_URL_ID = 110

    old_list = []
    new_list = []

    random_list = []
    master_akid = '3D808279C54882A3C312EEDF990F5735489ED0CB'

    ex_serial = '10028015818766309226464494355'


    import random
    # old_list = random.sample(old_list, 5)

    new_list = ['1055965136913638756275944619', '25019381422291326016234169286', '38604205910516199250541591589', '26351170549277952125406067382', '26470410281959639070536568135']



    from collections import defaultdict
    ans = defaultdict(lambda: dict())
    import time

    d = {}
    for element in new_list:
        d_d = {}
        serial_number = element
        for c in range(2):
            data = make_ocsp_query(serial_number=serial_number, akid=master_akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            time.sleep(10)
            d_d[c] = data
        d[serial_number] = d_d
    ans['new'] = d


    with open("cache_exp.json", "w") as ouf:
        json.dump(ans, fp=ouf, indent=2)






