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
****** Showing different policies for a same OCSP url

http://ocsps.ssl.com  (False: 554, True: 59946)
http://ocsp.visa.com/ocsp  (False: 1325, True: 6402)

-- Finding OCSP urls that serve both delegated and undelegated responses -> 264, 49
SELECT ocsp_url_id, COUNT(DISTINCT delegated_response) as c
from ocsp_response_wrt_asn
WHERE ocsp_response_status = 'OCSPResponseStatus.SUCCESSFUL' and ocsp_cert_status in ('OCSPCertStatus.GOOD', 'OCSPCertStatus.REVOKED')
GROUP by ocsp_url_id
ORDER by c DESC;

SELECT * from ocsp_host WHERE id in (49, 264);

SELECT delegated_response,count(*) from ocsp_response_wrt_asn
WHERE ocsp_response_status = 'OCSPResponseStatus.SUCCESSFUL' and ocsp_cert_status in ('OCSPCertStatus.GOOD', 'OCSPCertStatus.REVOKED')
and ocsp_url_id = 49
GROUP by delegated_response;

SELECT delegated_response,count(*) from ocsp_response_wrt_asn
WHERE ocsp_response_status = 'OCSPResponseStatus.SUCCESSFUL' and ocsp_cert_status in ('OCSPCertStatus.GOOD', 'OCSPCertStatus.REVOKED')
and ocsp_url_id = 264
GROUP by delegated_response;
-------------------------------------------------------------------------------------------------------------------------------------------


*** Latency for fetching OCSP responses from different responders from different ASN

*** TIMEOUT frequency for different OCSP responders

*** Error response rate different OCSP responders

Diverging Bars

->> Error er histogram distribution?? Population Pyramid

Time Series Plot for jitter

*** Propagation Delay

******* Error Messages: Do we Dive in?

Latency Variation from different ASNs...

******** good and bad for same cert??

http://ocsp.sectigochina.com

June and July
----------------------------------------
SELECT serial, akid, fingerprint, ocsp_url_id, count(DISTINCT ocsp_cert_status)
from ocsp_response_wrt_asn
WHERE ocsp_response_status = 'OCSPResponseStatus.SUCCESSFUL'
and ocsp_cert_status in ('OCSPCertStatus.GOOD', 'OCSPCertStatus.REVOKED')
group by serial, akid, fingerprint, ocsp_url_id
ORDER by count(DISTINCT ocsp_cert_status) desc, serial asc;
---------------------------------------------
'''


TOTAL_CERTS = get_total_cert_per_ocsp_url()







