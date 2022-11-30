import time

from OCSP_DNS_DJANGO.loominati_helper_tools import get_ocsp_hosts_v2
from OCSP_DNS_DJANGO.models import *
from collections import defaultdict
import pyasn, json
from multiprocessing.dummy import Pool as ThreadPool
from OCSP_DNS_DJANGO.practise_ground.cache_exp_prac import *

# TODO check pyasn, intervaltree

# from caching_strategy_master_v2 import *

from OCSP_DNS_DJANGO.tools import get_dns_records, AS2ISP, get_base_url

asndb = pyasn.pyasn('OCSP_DNS_DJANGO/ipsan_db.dat')
as2isp = AS2ISP()


url_to_a_record = {}
mother_dict = {}


def send_query(ocsp_url, serial_number, akid):
    d = {}
    d['serial_number'] = serial_number
    ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
    ca_cert = pem.readPemFromString(ca_cert)
    issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
    ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)
    headers = get_ocsp_request_headers(ocsp_host)
    ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                              userCert=None, add_nonce=False)
    dd = encoder.encode(ocspReq)
    response = requests.post(ocsp_url, data=dd, headers=headers)
    decoded_response = return_ocsp_result(response.content, is_bytes=True)

    d['response_status'] = str(decoded_response.response_status)
    if str(decoded_response.response_status) == "OCSPResponseStatus.SUCCESSFUL":
        d['cert_status'] = str(decoded_response.certificate_status)
        d['produced_at'] = str(decoded_response.produced_at)
        d['this_update'] = str(decoded_response.this_update)
        d['next_update'] = str(decoded_response.next_update)
        # d['signature'] = str(decoded_response.signature)
        delegated_responder = -1
        try:
            if len(decoded_response.certificates) > 0:
                delegated_responder = True
            elif len(decoded_response.certificates) == 0:
                delegated_responder = False
        except:
            pass
        d['is_delegated'] = delegated_responder
    return d

def exp_init(ocsp_url):
    global mother_dict
    try:
        q_key = "ocsp:serial:" + ocsp_url
        elements = r.lrange(q_key, 0, -1)
        elements = [e.decode() for e in elements]
        d = {}
        for element in elements:
            try:
                serial_number, akid, fingerprint = element.split(":")
                d_d = send_query(ocsp_url=ocsp_url,
                                 serial_number=serial_number,
                                 akid=akid)
                d[serial_number] = d_d
            except:
                pass
        mother_dict[ocsp_url] = d
    except Exception as e:
        pass
# sudo service apache2 stop 3.220

def caching_exp(index):
    global mother_dict
    mother_dict = {}
    ocsp_hosts = get_ocsp_hosts_v2(redis_host=redis_host)
    # exlude 'ocsp.pki.goog'

    final_hosts = []
    for e in ocsp_hosts:
        if 'ocsp.pki.goog' not in e:
            final_hosts.append(e)

    pool = ThreadPool(80)
    results = pool.map(exp_init, final_hosts)
    pool.close()
    pool.join()

    # TODO create
    with open('ocsp_dump/file_{}.json'.format(index), "w") as ouf:
        json.dump(mother_dict, fp=ouf)

    # # # # # # #
    ###base url###

# ocsp_url_analizer()
# caching_exp()

index = 0

while(True):
    try:
        index += 1
        print("Starting {}".format(index))
        caching_exp(index=index)
        time.sleep(60 * 10)
    except:
        pass


