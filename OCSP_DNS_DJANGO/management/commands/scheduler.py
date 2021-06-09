import logging

import django
django.setup()

from apscheduler.schedulers.blocking import BlockingScheduler
from django.conf import settings
from django.core.management.base import BaseCommand
from django_apscheduler.jobstores import DjangoJobStore
import aiohttp
import asyncio
import requests
import time

logger = logging.getLogger(__name__)
import concurrent
import redis
from OCSP_DNS_DJANGO.local import INTERVAL_TYPE, INTERVAL_VAL, LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST

if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST


r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")

import redis
from OCSP_DNS_DJANGO.models import *

from OCSP_DNS_DJANGO.tools import fix_cert_indentation, get_dns_records

from cryptography.x509 import ocsp
import binascii
import hashlib
import time

from OCSP_DNS_DJANGO.pyasn1_modules import rfc2560
from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
from OCSP_DNS_DJANGO.pyasn1_modules import pem
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import univ


def return_ocsp_result(ocsp_response):
    """ Extract the OCSP result from the provided ocsp_response """
    try:
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_response.content)
        return ocsp_response

    except ValueError as err:
        return f"{str(err)}"


sha1oid = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))


def makeOcspRequest(issuerCert, userSerialNumber=None, userCert=None, add_nonce=False):
    issuerTbsCertificate = issuerCert.getComponentByName('tbsCertificate')
    if (userCert is None):
        issuerSubject = issuerTbsCertificate.getComponentByName('subject')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    else:
        c = pem.readPemFromString(userCert)
        userCert, _ = decoder.decode(c, asn1Spec=rfc2459.Certificate())
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        issuerSubject = userTbsCertificate.getComponentByName('issuer')

        issuerHash = hashlib.sha1(
            encoder.encode(issuerSubject)
        ).digest()

    issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName(
        'subjectPublicKey')

    issuerKeyHash = hashlib.sha1(issuerSubjectPublicKey.asOctets()).digest()

    if (userSerialNumber is None):
        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')
        userSerialNumber = userTbsCertificate.getComponentByName('serialNumber')

    request = rfc2560.Request()
    reqCert = request.setComponentByName('reqCert').getComponentByName('reqCert')

    hashAlgorithm = reqCert.setComponentByName('hashAlgorithm').getComponentByName('hashAlgorithm')
    hashAlgorithm.setComponentByName('algorithm', sha1oid)

    reqCert.setComponentByName('issuerNameHash', issuerHash)
    reqCert.setComponentByName('issuerKeyHash', issuerKeyHash)
    reqCert.setComponentByName('serialNumber', str(int(userSerialNumber, 16)))

    ocspRequest = rfc2560.OCSPRequest()

    tbsRequest = ocspRequest.setComponentByName('tbsRequest').getComponentByName('tbsRequest')
    tbsRequest.setComponentByName('version', 'v1')

    if (add_nonce):
        requestExtensions = tbsRequest.setComponentByName('requestExtensions').getComponentByName('requestExtensions')

        extension = rfc2459.Extension()
        extension.setComponentByName('extnID', rfc2560.id_pkix_ocsp_nonce)
        extension.setComponentByName('critical', 0)

        nonce = "0410EAE354B142FE6DE525BE7708307F80C2"
        nonce = nonce[:-10] + str(int(time.time()))
        ## ASN1: Tag (04: Integer) - Length (10:16 bytes) - Value  Encoding
        ## See: http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art062
        ## current version of pyasn1_modules do not support nonce

        extension.setComponentByName('extnValue', binascii.unhexlify(nonce))

        requestExtensions.setComponentByPosition(0, extension)

    requestList = tbsRequest.setComponentByName('requestList').getComponentByName('requestList')
    requestList.setComponentByPosition(0, request)
    return ocspRequest


def get_ocsp_host(ocsp_url):
    ocsp_host = ocsp_url
    if ocsp_host.startswith("http://"):
        ocsp_host = ocsp_host[7:]
    if "/" in ocsp_host:
        ocsp_host = ocsp_host[0: ocsp_host.find("/")]
    return ocsp_host


def get_ocsp_request_headers(ocsp_host):
    headers = {'Connection': 'Keep-Alive', \
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', \
               'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0", \
               'Content-Type': 'application/ocsp-request', \
               'Host': ocsp_host
               }
    return headers


'''
    In my experience, one of the reasons you get an 
    "unauthorized" response is when you ask the CA 
    for the status of a certificate that it did not sign. 
    In other words, a certificate signed by a different CA. 
    In this case, the OCSP response is meant to indicate 
    that it is not authorized to tell you whether the 
    certificate is Good or Revoked.
'''

async def process_certs(ocsp_url, elements):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for element in elements:
            task = asyncio.ensure_future(process_cert(session, ocsp_url, element))
            tasks.append(task)

        await asyncio.gather(*tasks)


def unit_ocsp_url_process_v2(ocsp_url):
    ocsp_url_instance = None

    if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
        ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
        dns_records = get_dns_records(ocsp_url)
        for record in dns_records:
            dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
    else:
        ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)

    q_key = "ocsp:serial:" + ocsp_url
    elements = r.lrange(q_key, 0, -1)
    elements = [e.decode() for e in elements]

    logger.info("Processing total {} certificate for ocsp url {}".format(len(elements), ocsp_url))

    for element in elements:
        try:
            serial_number, akid, fingerprint = element.split(":")

            if ocsp_data.objects.filter(ocsp_url=ocsp_url_instance, serial=serial_number).exists():
                continue

            ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
            ca_cert = pem.readPemFromString(ca_cert)
            issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

            ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

            headers = get_ocsp_request_headers(ocsp_host)

            ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)), userCert=None,
                                      add_nonce=False)

            import requests as r_req
            response = r_req.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=5)
            decoded_response = return_ocsp_result(response)

            if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
                ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                         fingerprint=fingerprint,
                                         ocsp_response=response,
                                         ocsp_response_status=str(decoded_response.response_status))
            else:
                delegated_responder = False
                if len(decoded_response.certificates) > 0:
                    delegated_responder = True
                ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                         fingerprint=fingerprint,
                                         delegated_response=delegated_responder, ocsp_response=response,
                                         ocsp_response_status=str(decoded_response.response_status))

        except Exception as e:
            logger.error("Error in Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url, e))

def unit_ocsp_url_process(ocsp_url):
    ocsp_url_instance = None
    if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
        ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
        dns_records = get_dns_records(ocsp_url)
        for record in dns_records:
            dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
    else:
        ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)

    q_key = "ocsp:serial:" + ocsp_url
    elements = r.lrange(q_key, 0, -1)
    elements = [e.decode() for e in elements]

    logger.info("Processing total {} certificate for ocsp url {}".format(len(elements), ocsp_url))

    for element in elements:
        try:
            serial_number, akid, fingerprint = element.split(":")

            if ocsp_data.objects.filter(ocsp_url=ocsp_url_instance, serial=serial_number).exists():
                continue

            ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
            ca_cert = pem.readPemFromString(ca_cert)
            issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

            ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

            headers = get_ocsp_request_headers(ocsp_host)

            ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)), userCert=None,
                                      add_nonce=False)

            import requests as r_req
            response = r_req.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=5)
            decoded_response = return_ocsp_result(response)

            if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
                ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                         fingerprint=fingerprint,
                                         ocsp_response=response.content,
                                         ocsp_response_status=str(decoded_response.response_status))
            else:
                delegated_responder = False
                if len(decoded_response.certificates) > 0:
                    delegated_responder = True
                ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                         fingerprint=fingerprint,
                                         delegated_response=delegated_responder, ocsp_response=response,
                                         ocsp_response_status=str(decoded_response.response_status))

        except Exception as e:
            logger.error("Error in Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url, e))


def ocsp_job_mp():
    t1 = time.perf_counter()
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(unit_ocsp_url_process, ocsp_urls_lst)

    t2 = time.perf_counter()

    logger.info("Scheduler Job Finished in {} seconds".format(t2 - t1))


def ocsp_job():
    t1 = time.perf_counter()

    logger.info("Starting ocsp job now !")
    r = redis.Redis(host=redis_host, port=6379, db=0, password="certificatesarealwaysmisissued")
    ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
    ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]

    logger.info("Processing total {} ocsp urls".format(len(ocsp_urls_lst)))

    for ocsp_url in ocsp_urls_lst:
        ocsp_url_instance = None
        if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
            ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
            dns_records = get_dns_records(ocsp_url)
            for record in dns_records:
                dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
        else:
            ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)



        q_key = "ocsp:serial:" + ocsp_url
        elements = r.lrange(q_key, 0, -1)
        elements = [e.decode() for e in elements]
        elements = elements[0: 5]

        logger.info("Processing total {} certificate for ocsp url {}".format(len(elements), ocsp_url))

        for element in elements:
            try:
                serial_number, akid, fingerprint = element.split(":")

                if ocsp_data.objects.filter(ocsp_url=ocsp_url_instance, serial=serial_number).exists():
                    continue

                ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
                ca_cert = pem.readPemFromString(ca_cert)
                issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())

                ocsp_host = get_ocsp_host(ocsp_url=ocsp_url)

                headers = get_ocsp_request_headers(ocsp_host)

                ocspReq = makeOcspRequest(issuerCert=issuerCert, userSerialNumber=hex(int(serial_number)), userCert=None, add_nonce=False)

                import requests as r_req
                response = r_req.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=10)
                decoded_response = return_ocsp_result(response)

                if str(decoded_response.response_status) != "OCSPResponseStatus.SUCCESSFUL":
                    ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                             fingerprint=fingerprint,
                                             ocsp_response=response.content,
                                             ocsp_response_status=str(decoded_response.response_status))
                else:
                    delegated_responder = False
                    if len(decoded_response.certificates) > 0:
                        delegated_responder = True
                    ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid,
                                             fingerprint=fingerprint,
                                             delegated_response=delegated_responder, ocsp_response=response,
                                             ocsp_response_status=str(decoded_response.response_status))

            except Exception as e:
                logger.error("Error in Processing cert serial {} for ocsp url {} ({})".format(serial_number, ocsp_url, e))

    t2 = time.perf_counter()
    print(f'Finished in {t2 - t1} seconds')


class Command(BaseCommand):

    def handle(self, *args, **options):
        scheduler = BlockingScheduler(timezone=settings.TIME_ZONE)
        scheduler.add_jobstore(DjangoJobStore(), "default")

        scheduler.add_job(
            ocsp_job_mp,
            'interval',  # Every hour
            hours=1,
            max_instances=1,
            replace_existing=True,
        )

        try:
            logger.info("Starting scheduler...")
            scheduler.start()
        except KeyboardInterrupt:
            logger.info("Stopping scheduler...")
            scheduler.shutdown()
            logger.info("Scheduler shut down successfully!")