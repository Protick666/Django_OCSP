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


def check_sanity():
    elements = OcspResponsesWrtAsn.objects.filter(ocsp_response_status='OCSPResponseStatus.SUCCESSFUL')
    for element in elements:
        ocsp_response = return_ocsp_result(element.ocsp_response_as_bytes, is_bytes=True)
        passed = True
        if str(ocsp_response.certificate_status) != element.ocsp_cert_status:
            print("XXX")
            passed = False
        if str(ocsp_response.serial_number) != element.serial:
            print("XXX")
            passed = False
        print(passed)
