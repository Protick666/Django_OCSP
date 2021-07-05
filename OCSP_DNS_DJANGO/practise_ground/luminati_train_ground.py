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


def luminati_master_crawler_cache(ocsp_url, ip_host, master_akid, OCSP_URL_ID, cdn, key):

    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")

    certs_per_bucket = 4
    query_number = 100

    random_list = []

    ex_serial = '10028015818766309226464494355'

    old_list = OcspResponsesWrtAsn.objects.filter(ocsp_url_id=OCSP_URL_ID,
                                                       ocsp_response_status='OCSPResponseStatus.SUCCESSFUL',
                                                       ocsp_cert_status='OCSPCertStatus.GOOD')[0: 2000]

    old_set = set()
    for element in old_list:
        old_set.add(element.serial)

    old_list = list(old_set)[0: certs_per_bucket]
    import random
    # old_list = random.sample(old_list, 5)

    q_key = "ocsp:serial:" + ocsp_url
    elements = r.lrange(q_key, 0, -1)
    elements = [e.decode() for e in elements]
    elements = list(set(elements))
    elements = random.sample(elements, certs_per_bucket)
    new_list = elements

    for i in range(certs_per_bucket):
        random_list.append(random_with_N_digits(len(ex_serial)))

    from collections import defaultdict
    ans = defaultdict(lambda: dict())
    import time

    d = {}
    for e in old_list:
        d_d = {}
        for c in range(query_number):
            data = make_ocsp_query(serial_number=e, akid=master_akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            # time.sleep(60)
            d_d[c] = data
        d[e] = d_d
    ans['old'] = d

    d = {}
    for element in new_list:
        d_d = {}
        serial_number, akid, fingerprint = element.split(":")
        for c in range(query_number):
            data = make_ocsp_query(serial_number=serial_number, akid=akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            #time.sleep(60)
            d_d[c] = data
        d[serial_number] = d_d
    ans['new'] = d

    d = {}
    for e in random_list:
        d_d = {}
        for c in range(query_number):
            data = make_ocsp_query(serial_number=e, akid=master_akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            #time.sleep(60)
            d_d[c] = data
        d[e] = d_d
    ans['random'] = d

    with open("{}-cache_exp-{}-{}.json".format(cdn, key, time.time()), "w") as ouf:
        json.dump(ans, fp=ouf, indent=2)


import time

def cache_exp_init():
    d = {}
    d['cloudflare'] = {}
    d['akamai1'] = {}
    d['akamai2'] = {}

    ## Info for cloudflare

    d['cloudflare']["ocsp_url"] = 'http://ocsp2.globalsign.com/gsdomainvalsha2g3'
    d['cloudflare']["ip_host"] = 'http://104.18.21.226/gsdomainvalsha2g3'
    d['cloudflare']["master_akid"] = '3D808279C54882A3C312EEDF990F5735489ED0CB'
    d['cloudflare']["OCSP_URL_ID"] = 110
    d['cloudflare']["cdn"] = "cloudflare"

    d['akamai1']["ocsp_url"] = 'http://nazwassl2sha2.ocsp-certum.com'
    d['akamai1']["ip_host"] = 'http://23.212.251.132'
    d['akamai1']["master_akid"] = '54DC90BB9D471951C379682C84ED2EDF5F46BAC7'
    d['akamai1']["OCSP_URL_ID"] = 81
    d['akamai1']["cdn"] = "akamai"

    d['akamai2']["ocsp_url"] = 'http://r3.o.lencr.org'
    d['akamai2']["ip_host"] = 'http://23.205.105.167'
    d['akamai2']["master_akid"] = '142EB317B75856CBAE500940E61FAF9D8B14C2C6'
    d['akamai2']["OCSP_URL_ID"] = 125
    d['akamai2']["cdn"] = "akamai"

    for i in range(3):
        for key in d:
            luminati_master_crawler_cache(ocsp_url=d[key]['ocsp_url'],
                                          ip_host=d[key]['ip_host'], master_akid=d[key]['master_akid'],
                                          OCSP_URL_ID=d[key]['OCSP_URL_ID'], cdn=d[key]['cdn'], key=key)
            time.sleep(120)
        time.sleep(1800)


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

    random_list = ['47901382578257582476611959918', '94606194882573272956985698604', '77292347294016299247283911213', '90090007779075498731559960921', '65099188835406091494518264786']



    from collections import defaultdict
    ans = defaultdict(lambda: dict())
    import time

    d = {}
    for element in random_list:
        d_d = {}
        serial_number = element
        for c in range(2):
            data = make_ocsp_query(serial_number=serial_number, akid=master_akid, r=r, ocsp_url=ocsp_url, ip_host=ip_host)
            time.sleep(10)
            d_d[c] = data
        d[serial_number] = d_d
    ans['random'] = d


    with open("cache_exp.json", "w") as ouf:
        json.dump(ans, fp=ouf, indent=2)






