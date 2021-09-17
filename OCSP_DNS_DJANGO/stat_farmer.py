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

r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")

'''
Showing different policies for a same OCSP url

Latency for fetching OCSP responses from different responders from different ASN

TIMEOUT frequency for different OCSP responders

Error response rate different OCSP responders

Diverging Bars

->>Error er histogram distribution?? Population Pyramid

Time Series Plot for jitter


Propagation Delay

Error Messages: Do we Dive in?

Latency Variation from different ASNs...

good and bad for same cert??

'''


TOTAL_CERTS = get_total_cert_per_ocsp_url()







