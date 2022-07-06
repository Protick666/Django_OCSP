import json
import logging
from pathlib import Path

import django
import dns.resolver
import dns.resolver
import redis
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
    return_ocsp_result, get_ocsp_request_headers_as_tuples
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.tools import fix_cert_indentation

django.setup()

logger = logging.getLogger(__name__)

mother_dict = {}

if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

# synced_data = {}

r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")


def process_ocsp_urls_sync(ocsp_url, chosen_hop_list, url_index, element, dns_server, is_nonce):
    import requests
    import time

    ocsp_response_time = []
    dns_response_time = []
    iterations = 100
    # TODO
    target_iter = 20

    # synced_data[ocsp_url] = element

    serial_number, akid, fingerprint = element["serial"], element["akid"], element["fingerprint"]
    akk = r.get("ocsp:akid:" + akid)
    # print(akid)
    ca_cert = fix_cert_indentation(akk.decode())

    ca_cert = pem.readPemFromString(ca_cert)
    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
    headers = get_ocsp_request_headers_as_tuples(ocsp_host)

    headers = {e[0]: e[1] for e in headers}

    index = 1
    for i in range(iterations):
        try:
            ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                      userCert=None, add_nonce=is_nonce)
            t_start = time.perf_counter()
            result_data = requests.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=10)
            t_total = time.perf_counter() - t_start
            a = 1
            decoded_response = return_ocsp_result(result_data.content, is_bytes=True)
            if isinstance(decoded_response, str) and isinstance(result_data, bytes):
                raise Exception(result_data.decode())
            ocsp_response_time.append(t_total)

            if index == target_iter:
                break
            index += 1
            time.sleep(1)
        except Exception as e:
            a = 1

    if dns_server != "doh":
        index = 1
        import random
        specifier = random.randint(1, 10000)
        dns_query = "{}.ttlexp.exp.net-measurement.net".format(specifier)
        for i in range(iterations):
            try:
                my_resolver = dns.resolver.Resolver()
                # 8.8.8.8 is Google's public DNS server
                my_resolver.nameservers = [dns_server]
                t_start = time.perf_counter()
                answer = my_resolver.resolve(dns_query, rdtype=dns.rdatatype.TXT)
                t_total = answer.response.time
                ttl = answer.response.answer[0].ttl
                dns_response_time.append((t_total, ttl))

                if index == target_iter:
                    break
                index += 1
                time.sleep(1)
            except Exception as e:
                a = 1
    else:
        index = 1
        import random
        specifier = random.randint(1, 10000)
        dns_query = "{}.ttlexp.exp.net-measurement.net".format(specifier)
        for i in range(iterations):
            try:
                t_start = time.perf_counter()
                res = requests.get(
                    "https://cloudflare-dns.com/dns-query?name={}&type=txt".format(dns_query),
                    headers={"accept": "application/dns-json"})
                t_total = time.perf_counter() - t_start
                answer = json.loads(res.text)['Answer'][0]
                ttl = answer['TTL']
                dns_response_time.append((t_total, ttl))

                if index == target_iter:
                    break
                index += 1
                time.sleep(1)
            except Exception as e:
                a = 1



    to_Save = {
        "ocsp": ocsp_response_time,
        "dns": dns_response_time
    }

    if ocsp_url not in mother_dict:
        mother_dict[ocsp_url] = {}
    if dns_server not in mother_dict[ocsp_url]:
        mother_dict[ocsp_url][dns_server] = {}
    mother_dict[ocsp_url][dns_server][is_nonce] = to_Save




def http_vs_dns():
    d = ['http://ocsp.trust-provider.cn', 'http://ocsp.netsolssl.com', 'http://ocsp.quovadisglobal.com',
         'http://oneocsp.microsoft.com/ocsp', 'http://status.rapidssl.com']

    f = open("sync_elements.json")
    element_dict = json.load(f)

    # ocsp_urls_lst = list(dd.keys())
    # ocsp_urls_lst = [e for e in ocsp_urls_lst if e in d]

    # TODO change it
    if LOCAL:
        local_ip = "75.75.75.75"
    else:
        local_ip = "198.82.247.98"
    dns_servers = ["1.1.1.1", "8.8.8.8", local_ip, "doh"]

    url_index = 0
    for ocsp_url in d:
        for dns_server in dns_servers:
            for is_nonce in [True, False]:
                url_index += 1
                process_ocsp_urls_sync(ocsp_url=ocsp_url,
                                       chosen_hop_list=None, url_index=url_index,
                                       element=element_dict[ocsp_url],
                                       dns_server=dns_server, is_nonce=is_nonce)

    parent_path = 'ocsp_dns_http/'
    Path(parent_path).mkdir(parents=True, exist_ok=True)
    with open(parent_path + "allover.json", "w") as ouf:
        json.dump(mother_dict, fp=ouf)
    # with open(parent_path + "sync_elements.json", "w") as ouf:
    #     json.dump(synced_data, fp=ouf)