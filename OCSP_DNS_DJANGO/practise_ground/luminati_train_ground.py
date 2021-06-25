import logging

import django

from OCSP_DNS_DJANGO.management.commands.scheduler import get_ocsp_host, makeOcspRequest, \
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

from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder


def luminati_master_crawler_debug():

    logger.info("Starting ocsp job now !")
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    # ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    # ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]
    ocsp_urls_lst = ['http://ocsp.sectigochina.com']
    # Tune here

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    # 240*214*20*.002333
    url_count = 0
    for ocsp_url in ocsp_urls_lst:
        logger.info("Processed total {} ocsp urls".format(url_count))
        url_count += 1

        tu = ('81192179725040481647048356377781389991', 'C6545E5A649886C3FBD40F48892B5B2BF3B120AF', 'e93960a575ac256d7f64267fe626fa6dfc7b18dd21792cb7baf9e3efc9673726')

        serial_number, akid, fingerprint = tu[0], tu[1], tu[2]


        ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
        ca_cert = pem.readPemFromString(ca_cert)
        issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

        ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

        ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)),
                                  userCert=None, add_nonce=False)

        asn_list = ['10796', '11776', '133612', '25144', '29571', '35805', '43940']


        headers = get_ocsp_request_headers_as_tuples(ocsp_host)


        for c in asn_list:
            try:
                import urllib.request
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler(
                        {
                            'http': 'http://lum-customer-c_9c799542-zone-residential-asn-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(
                                c)}))
                opener.addheaders = headers
                bb = opener.open(ocsp_url, data=encoder.encode(ocspReq))
                # per_cert_dict = {}
                # for header in bb.headers.keys():
                #     if header.startswith('x-luminati'):
                #         per_cert_dict[header] = bb.headers[header]

                b = bb.read()
                decoded_response = return_ocsp_result(b, is_bytes=True)

                # print(type(decoded_response))

                if str(decoded_response.response_status) == "OCSPResponseStatus.SUCCESSFUL":
                    print(decoded_response.certificate_status)
            except Exception as e:
                a = 1

