import logging

import django

from OCSP_DNS_DJANGO.management.commands.scheduler import return_ocsp_result
from OCSP_DNS_DJANGO.models import *

django.setup()
logger = logging.getLogger(__name__)

from collections import defaultdict

d_url = defaultdict(lambda : 0)
d_asn = defaultdict(lambda : 0)
d_url_to_responder_hash = defaultdict(lambda : set())

def check_sanity():
    count = 0
    elements = OcspResponsesWrtAsn.objects.filter(ocsp_response_status='OCSPResponseStatus.SUCCESSFUL')
    for element in elements:
        ocsp_response = return_ocsp_result(element.ocsp_response_as_bytes, is_bytes=True)
        if str(ocsp_response.certificate_status) != element.ocsp_cert_status or str(ocsp_response.serial_number) != element.serial:
            count += 1
            d_url[element.ocsp_url.url] += 1

            d_url_to_responder_hash[element.ocsp_url.url].add(ocsp_response.responder_key_hash)

            d_asn[element.asn] += 1
            print("Found one {}".format(element.id))
    print("Bad eggs: ", count)
    logger.info("Bad eggs: {}".format(count))

    print("Bad ocsp urls")
    print(d_url)

    print("Responder")
    print(d_url_to_responder_hash)

    print("Bad asns")
    print(d_asn)
