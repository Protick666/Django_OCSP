import json
import logging
import time
from random import randint
import dill as pickle
import traceback


import django
import requests

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers
from OCSP_DNS_DJANGO.models import OcspResponsesWrtAsn

django.setup()
from datetime import datetime
logger = logging.getLogger(__name__)
import redis
from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST

if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST


r = redis.Redis(host=redis_host, port=6379, db=4, password="certificatesarealwaysmisissued")

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


def get_ocsp_host_suffix(ocsp_url):
    ocsp_host = ocsp_url
    if ocsp_host.startswith("http://"):
        ocsp_host = ocsp_host[7:]

    if "/" in ocsp_host:
        ocsp_host = ocsp_host[ocsp_host.find("/"):]
        return ocsp_host
    return None


def make_ocsp_query(serial_number, akid, r, ocsp_url, ip_host, nonce, pre, ocspReq, headers):

    response = None


    try:
        d = {}
        d['serial_number'] = serial_number

        # starting_time = time.monotonic()
        # response_temp = requests.get(ip_host)
        # connection_time = time.monotonic() - starting_time - response_temp.elapsed.total_seconds()
        # d['connection_time'] = connection_time

        dd = encoder.encode(ocspReq)
        starting_time = time.monotonic()
        response = requests.post(ip_host, data=dd, headers=headers)
        response_time = time.monotonic() - starting_time
        decoded_response = return_ocsp_result(response.content, is_bytes=True)

        d['response_len'] = len(response.content)

        d['response_status'] = str(decoded_response.response_status)
        d['response_headers'] = dict(response.headers)

        has_nonce = False

        try:
            for e in list(decoded_response.extensions):
                if '1.3.6.1.5.5.7.48.1.2' in (str(e.oid)):
                    has_nonce = True
            d['has_nonce'] = has_nonce
        except:
            pass

        # d['response_status'] = str(decoded_response.response_status)

        if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
            a = 1

        if str(decoded_response.response_status) == "OCSPResponseStatus.SUCCESSFUL":
            d['cert_status'] = str(decoded_response.certificate_status)
            d['produced_at'] = str(decoded_response.produced_at)
            d['this_update'] = str(decoded_response.this_update)
            d['next_update'] = str(decoded_response.next_update)
            now = datetime.now()
            d['now'] = str(now)



            # d['signature'] = str(decoded_response.signature)

            delegated_responder = False

            try:
                if len(decoded_response.certificates) > 0:
                    delegated_responder = True
            except:
                pass

            d['is_delegated'] = delegated_responder

            # if pre[0] == -1:
            #     d['sig_same'] = True
            # else:
            #     d['sig_same'] = (pre[0] == str(decoded_response.signature))
            # pre[0] = str(decoded_response.signature)

        d['elapsed_time'] = response.elapsed.total_seconds()
        d['response_time'] = response_time
        #print("yo {}".format(ocsp_url))
        return d

    except Exception as e:
        # print(e)
        #d = {}
        d['error'] = str(e) + " " + str(decoded_response) + " " + str(response)
        if response:
            d['elapsed_time'] = response.elapsed.total_seconds()
        print("Doing 2")
        return d


def get_ips_of_urls():
    r = redis.Redis(host=redis_host, port=6379, db=4, password="certificatesarealwaysmisissued")
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


ex_serial = '10028015818766309226464494355'

f = open("ski_to_cert.json")
skid_to_cert = json.load(f)
def get_cert(akid):
    cert_string = skid_to_cert[akid.upper()]
    return cert_string

def mid_exp(serial_number, akid, query_number, ocsp_url, ip_host, nonce=False):
    d_d = {"with_nonce": {}, "without_nonce": {}}

    #print("{} {}".format(ocsp_url, serial_number))

    #print(ocsp_url, serial_number, akid)

    ca_cert = get_cert(akid)
    ca_cert = pem.readPemFromString(ca_cert)
    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
    headers = get_ocsp_request_headers(ocsp_host)

    if nonce is False:
        pre = [-1]

        ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                  userCert=None, add_nonce=False)

        for c in range(query_number):
            temp_serial = serial_number

            data = make_ocsp_query(serial_number=temp_serial,
                                   akid=akid, r=r, ocsp_url=ocsp_url,
                                   ip_host=ip_host, nonce=False, pre=pre, ocspReq=ocspReq, headers=headers)
            # print(c, data)
            # time.sleep(1)
            d_d['without_nonce'][c] = data


    if nonce:
        pre = [-1]
        for c in range(query_number):
            temp_serial = serial_number

            ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                      userCert=None, add_nonce=True)
            data = make_ocsp_query(serial_number=temp_serial,
                                   akid=akid, r=r, ocsp_url=ocsp_url,
                                   ip_host=ip_host, nonce=True, pre=pre, ocspReq=ocspReq, headers=headers)
            # print(c, data)
            # time.sleep(1)
            d_d['with_nonce'][c] = data

    return d_d



def luminati_master_crawler_cache(tuple):
    try:
        ocsp_url, ip_host = tuple
        # print(tuple)
        print("Doing {} {}".format(ocsp_url, ip_host))
        ip_host = 'http://' + ip_host

        suffix = get_ocsp_host_suffix(ocsp_url)
        if suffix:
            ip_host = "{}{}".format(ip_host, suffix)
            # if not ip_host.endswith("/"):
            #     ip_host = ip_host + "/"

        r = redis.Redis(host=redis_host, port=6379, db=4, password="certificatesarealwaysmisissued")

        # TODO change
        certs_per_bucket = 1
        query_number = 10

        akid_c = None

        import random, time

        q_key = "{}-{}".format(0, ocsp_url)
        elements = r.lrange(q_key, 0, -1)
        elements = [e.decode() for e in elements]

        q_key = "{}-{}".format(1, ocsp_url)
        elements2 = r.lrange(q_key, 0, -1)
        elements2 = [e.decode() for e in elements2]
        elements = elements + elements2

        print("{}: Len of elements {}".format(ocsp_url, len(elements)))



        # print(ocsp_url)
        # elements = list(set(elements))
        # elements = random.sample(elements, certs_per_bucket)
        new_list = random.sample(elements, 60)
        # half_len = len(new_list) // 2
        no_nonce_list = new_list[: 50]
        nonce_list = new_list[50: ]

        from collections import defaultdict
        ans = defaultdict(lambda: dict())
        import time

        d = {}
        for element in no_nonce_list:
            serial_number_hex_str, fingerprint, akid = element.split(":")
            serial_number = int(serial_number_hex_str, 16)
            d_d = mid_exp(serial_number=serial_number, akid=akid, query_number=query_number, ocsp_url=ocsp_url,
                          ip_host=ip_host, nonce=False)
            d[serial_number] = d_d
            print("done 1")

        ans['no_nonce'] = d

        d = {}
        for element in nonce_list:
            serial_number_hex_str, fingerprint, akid = element.split(":")
            serial_number = int(serial_number_hex_str, 16)
            d_d = mid_exp(serial_number=serial_number, akid=akid, query_number=query_number, ocsp_url=ocsp_url,
                          ip_host=ip_host, nonce=True)
            d[serial_number] = d_d
            print("done 2")

        ans['nonce'] = d

        ans['url'] = ocsp_url

        return dict(ans), ocsp_url, ip_host
    except Exception as e:
        traceback.print_exc()
        print("err", e)
        return {}, ocsp_url, ip_host

    # try:
    #     with open("jsons_v11/{}-cache_exp-{}.json".format(cdn, time.time()), "w") as ouf:
    #         json.dump(ans, fp=ouf, indent=2)
    # except Exception as e:
    #     print(e)
    #     pass

    # return ans


def cache_exp_init_v5():
    from collections import defaultdict
    d = defaultdict(lambda : dict())


    ## Info for cloudflare
    # cloudflare globalsign done, now mocsp, akamai lc

    # d['highwind-1']["ocsp_url"] = 'http://ocsp.comodoca.com'
    # d['highwind-1']["ip_host"] = 'http://151.139.128.14'
    # d['highwind-1']["master_akid"] = '7E035A65416BA77E0AE1B89D08EA1D8E1D6AC765'
    # d['highwind-1']["cdn"] = "Highwind Networks"
    # #d['highwind-1']["ocsp_url"] = "ocsp.comodoca.com"
    # d['highwind-1']["meta"] = "Serves non-delegated OCSP response from others infrastructure"
    #
    # d['highwind-2']["ocsp_url"] = 'http://ocsp.sectigo.com'
    # d['highwind-2']["ip_host"] = 'http://151.139.128.14'
    # d['highwind-2']["master_akid"] = '8D8C5EC454AD8AE177E99BF99B05E1B8018D61E1'
    # d['highwind-2']["cdn"] = "Highwind Networks"
    # #d['highwind-2']["ocsp_url"] = "ocsp.sectigo.com"
    # d['highwind-2']["meta"] = "Serves non-delegated OCSP response from others infrastructure"
    #
    #
    # d['verizon']["ocsp_url"] = 'http://ocsp.digicert.com'
    # d['verizon']["ip_host"] = 'http://72.21.91.29'
    # d['verizon']["master_akid"] = None # TODO
    # d['verizon']["cdn"] = "Verizon"
    # #d['verizon']["ocsp_url"] = "ocsp.digicert.com"
    # d['verizon']["meta"] = "Serves non-delegated OCSP response from peer's infrastructure"



    d['Alibaba']["ocsp_url"] = 'http://ocsp.digicert.cn'
    d['Alibaba']["ip_host"] = 'http://47.246.23.118'
    d['Alibaba']["master_akid"] = None  # TODO
    d['Alibaba']["cdn"] = "Alibaba"
    #d['Alibaba']["ocsp_url"] = "ocsp.digicert.cn"
    d['Alibaba']["meta"] = "Serves non-delegated OCSP response from others infrastructure"


    # d['akamai']["ocsp_url"] = 'http://r3.o.lencr.org'
    # d['akamai']["ip_host"] = 'http://23.205.105.170'
    # d['akamai']["master_akid"] = '142EB317B75856CBAE500940E61FAF9D8B14C2C6'
    # #d['akamai']["ocsp_url"] = 'r3.o.lencr.org'
    # d['akamai']["cdn"] = "akamai"
    # d['akamai']["meta"] = "Serves non-delegated OCSP response from others infrastructure"

    # d['cloudflare']["ocsp_url"] = 'http://ocsp.msocsp.com'
    # d['cloudflare']["ip_host"] = 'http://104.18.25.243'
    # d['cloudflare']["master_akid"] = None
    # d['cloudflare']["cdn"] = "cloudflare"
    # #d['cloudflare']["ocsp_url"] = 'ocsp.msocsp.com'
    # d['cloudflare']["meta"] = "Serves delegated OCSP response from others infrastructure"

    # d['sukuri']["ocsp_url"] = 'http://ocsp.godaddy.com/'
    # d['sukuri']["ip_host"] = 'http://192.124.249.36'
    # d['sukuri']["master_akid"] = None
    # d['sukuri']["cdn"] = "sukuri"
    # #d['sukuri']["ocsp_url"] = 'ocsp.godaddy.com'
    # d['sukuri']["meta"] = "Serves delegated OCSP response from owner's infrastructure"

    # d['apple']["ocsp_url"] = 'http://ocsp.apple.com/ocsp03-apsrsa12g101'
    # d['apple']["ip_host"] = 'http://17.253.21.203/ocsp03-apsrsa12g101'
    # d['apple']["master_akid"] = None
    # d['apple']["cdn"] = "apple"
    # #d['apple']["ocsp_url"] = 'ocsp.apple.com/ocsp03-apsrsa12g101'
    # d['apple']["meta"] = "Serves delegated OCSP response from own infrastructure"
    #
    # d['amazon']["ocsp_url"] = 'http://ocsp.wisekey.com'
    # d['amazon']["ip_host"] = 'http://3.66.5.77'
    # d['amazon']["master_akid"] = None
    # d['amazon']["cdn"] = "amazon"
    # #d['amazon']["ocsp_url"] = 'ocsp.wisekey.com'
    # d['amazon']["meta"] = "Serves delegated OCSP response from other's infrastructure"

    # TODO do next ssocsp.cybertrust.ne.jp, ocsps.ssl.com

    for i in range(1):
        for key in d:
            try:
                for i in range(4):
                    luminati_master_crawler_cache(ocsp_url=d[key]['ocsp_url'],
                                                  ip_host=d[key]['ip_host'], master_akid=d[key]['master_akid'],
                                                  OCSP_URL_ID=1, cdn=d[key]['cdn'], key=key, meta=d[key]['is_delegated'])
                    #time.sleep(1)
            except Exception as e:
                pass
        #time.sleep(1800)


def cache_exp_init_v7():
    from collections import defaultdict
    d = defaultdict(lambda: dict())

    f = open('ocsp_url_info.json')
    d = json.load(f)
    s = set()

    seen_dict = {}

    for key in d:
        try:
            cdn = d[key]['org']

            if d[key]['root_domain'] in seen_dict:
                continue

            luminati_master_crawler_cache(ocsp_url=key,
                                          ip_host=d[key]['a_record'], master_akid=None,
                                          OCSP_URL_ID=1, cdn=d[key]['org'], key=key, meta=d[key]['is_delegated'])

            seen_dict[d[key]['root_domain']] = 1

        except Exception as e:
            print("Exception: {}-{}".format(key, e))

def get_redis_host():
    r = redis.Redis(host=redis_host, port=6379, db=4, password="certificatesarealwaysmisissued")
    return r


def dagaaa():
    # f = open("origin.json")
    # d = json.load(f)
    # ocsp_urls_list = []
    # for key in d:
    #     if d[key]['type'] == 3:
    #         ocsp_urls_list.append(key)
    # cache_exp_prac_selective.py
    # /Users/protick.bhowmick/PriyoRepos/OCSP_DNS_DJANGO/OCSP_DNS_DJANGO/practise_ground/cache_exp_prac_selective.py
    arr = []
    a = 1
    # ocsp_urls_list = ocsp_urls_list[-5 : ]
    # ocsp_urls_list = ['http://ocsp.sectigo.com']

    ocsp_urls_list = ['http://ocsp.sectigo.com', 'http://ocsp.int-r1.certainly.com', 'http://h.ocsp-certum.com', 'http://ocsp.global.sheca.com/ovscag5', 'http://ocsp.trust-provider.cn']



    for ocsp_url in ocsp_urls_list:
        try:
            records = get_dns_records(ocsp_url)
            a_records = [e[1] for e in records if e[0] == 'A_RECORD']
            arr.append((ocsp_url, a_records[0]))
        except:
            pass

    # epoch = int(time.time())
    # day_index = ((epoch // (24 * 60 * 60)) % 2 + 1) % 2
    # arr_with_count = []
    # for ocsp_url in ocsp_urls_list:
    #     q_key = "{}-{}".format(0, ocsp_url)
    #     elements = r.lrange(q_key, 0, -1)
    #     elements = [e.decode() for e in elements]
    #
    #     q_key = "{}-{}".format(1, ocsp_url)
    #     elements2 = r.lrange(q_key, 0, -1)
    #     elements2 = [e.decode() for e in elements2]
    #
    #     elements = elements + elements2
    #
    #     arr_with_count.append((len(elements), ocsp_url))
    # arr_with_count.sort()

    a = 1

    mother_dict = {}

    ii = time.time()

    from multiprocessing import Pool

    with Pool() as pool:
        for result in pool.imap_unordered(luminati_master_crawler_cache, arr):
            ans, ocsp_url, ip_host = result
            mother_dict[ocsp_url] = {
                "a_record": ip_host,
                "ans": ans
            }

    # for ocsp_url_ in ocsp_urls_set:
    #     ocsp_url = ocsp_url_.decode()
    #
    #     data = luminati_master_crawler_cache(ocsp_url=ocsp_url, ip_host=a_records[0])
    #     a = 1
    #     mother_dict[ocsp_url] = {
    #         "data": data,
    #         "records": records
    #     }

    a  = 1

    print("total time {}".format((time.time() - ii)/60))
    with open("discerning_data.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)
    a = 1
# do_it()








