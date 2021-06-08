# import redis
# from django.http import HttpResponse
# from .models import *
#
# from OCSP_DNS_DJANGO.tools import fix_cert_indentation, get_dns_records
#
# r = redis.Redis(host='pharah.cs.vt.edu', port=6379, db=0, password="certificatesarealwaysmisissued")
# import dns
# from cryptography.x509 import ocsp
# import os, random
# import binascii
# import subprocess
# import hashlib
# import time
#
# from OCSP_DNS_DJANGO.pyasn1_modules import rfc2560
# from OCSP_DNS_DJANGO.pyasn1_modules import rfc2459
# from OCSP_DNS_DJANGO.pyasn1_modules import pem
# from pyasn1.codec.der import decoder
# from pyasn1.codec.der import encoder
# from pyasn1.codec.native.encoder import encode as native_encoder
# from pyasn1.type import univ
#
# import base64
# import json
# import pprint
# import os
#
#
# def ocsp_crawler(request):
#     r = redis.Redis(host='pharah.cs.vt.edu', port=6379, db=0, password="certificatesarealwaysmisissued")
#     ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
#     ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]
#
#     for ocsp_url in ocsp_urls_lst:
#         if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
#             ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
#             dns_records = get_dns_records(ocsp_url)
#             for record in dns_records:
#                 dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
#         else:
#             ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)
#
#         q_key = "ocsp:serial:" + ocsp_url
#         elements = r.lrange(q_key, 0, -1)
#         elements = [e.decode() for e in elements]
#         for element in elements:
#             try:
#                 serial_number, akid, fingerprint = element.split(":")
#                 # "ocsp:akid:" + akid
#                 ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
#
#                 label = str(random.randint(1, 100000))
#                 file = open("OCSP_DNS_DJANGO/temp/{}.pem".format(label), "w")
#                 file.write(ca_cert)
#                 file.close()
#
#                 ocsp_host = ocsp_url
#                 if ocsp_host.startswith("http://"):
#                     ocsp_host = ocsp_host[7:]
#                 if "/" in ocsp_host:
#                     ocsp_host = ocsp_host[0: ocsp_host.find("/")]
#
#                 # https://serverfault.com/questions/466683/can-an-ssl-certificate-be-on-a-single-line-in-a-file-no-line-breaks
#                 # http://www.jfcarter.net/~jimc/documents/bugfix/21-openssl-ocsp.html
#                 # https://serverfault.com/questions/630975/ocsp-validation-unable-to-get-local-issuer-certificate
#
#                 request_cmd = 'ocsp -issuer OCSP_DNS_DJANGO/temp/{}.pem -serial '.format(label) + serial_number \
#                               + ' -url ' + ocsp_url + " -text -header host " + ocsp_host
#                 full_cmd = 'openssl' + " " + request_cmd
#
#                 out = subprocess.check_output(full_cmd, shell=True)
#                 out = out.decode()
#
#                 if "OCSP Response Status: successful" not in out:
#                     continue
#
#                 delegated_responder = False
#                 if "Certificate:" in out and "X509v3 Extended Key Usage" in out and "OCSP Signing" in out:
#                     delegated_responder = True
#
#                 ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid, fingerprint=fingerprint,
#                                          delegated_response=delegated_responder, ocsp_response=out)
#
#
#
#                 # print(delegated_responder)
#
#                 '''
#                     In my experience, one of the reasons you get an
#                     "unauthorized" response is when you ask the CA
#                     for the status of a certificate that it did not sign.
#                     In other words, a certificate signed by a different CA.
#                     In this case, the OCSP response is meant to indicate
#                     that it is not authorized to tell you whether the
#                     certificate is Good or Revoked.
#                 '''
#
#                 try:
#                     os.remove("OCSP_DNS_DJANGO/temp/{}.pem".format(label))
#                 except OSError:
#                     pass
#
#             except Exception as e:
#                 print("Exception")
#
#     return HttpResponse("asdas")
#
#
# sha1oid = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))
#
#
# def makeOcspRequest(issuerCert, userSerialNumber=None, userCert=None, add_nonce=False):
#     issuerTbsCertificate = issuerCert.getComponentByName('tbsCertificate')
#     if (userCert is None):
#         issuerSubject = issuerTbsCertificate.getComponentByName('subject')
#
#         issuerHash = hashlib.sha1(
#             encoder.encode(issuerSubject)
#         ).digest()
#
#     else:
#         c = pem.readPemFromString(userCert)
#         userCert, _ = decoder.decode(c, asn1Spec=rfc2459.Certificate())
#         userTbsCertificate = userCert.getComponentByName('tbsCertificate')
#         issuerSubject = userTbsCertificate.getComponentByName('issuer')
#
#         issuerHash = hashlib.sha1(
#             encoder.encode(issuerSubject)
#         ).digest()
#
#     issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName(
#         'subjectPublicKey')
#
#     issuerKeyHash = hashlib.sha1(issuerSubjectPublicKey.asOctets()).digest()
#
#     if (userSerialNumber is None):
#         userTbsCertificate = userCert.getComponentByName('tbsCertificate')
#         userIssuer = userTbsCertificate.getComponentByName('issuer')
#         userSerialNumber = userTbsCertificate.getComponentByName('serialNumber')
#
#     request = rfc2560.Request()
#     reqCert = request.setComponentByName('reqCert').getComponentByName('reqCert')
#
#     hashAlgorithm = reqCert.setComponentByName('hashAlgorithm').getComponentByName('hashAlgorithm')
#     hashAlgorithm.setComponentByName('algorithm', sha1oid)
#
#     reqCert.setComponentByName('issuerNameHash', issuerHash)
#     reqCert.setComponentByName('issuerKeyHash', issuerKeyHash)
#     reqCert.setComponentByName('serialNumber', str(int(userSerialNumber, 16)))
#
#     ocspRequest = rfc2560.OCSPRequest()
#
#     tbsRequest = ocspRequest.setComponentByName('tbsRequest').getComponentByName('tbsRequest')
#     tbsRequest.setComponentByName('version', 'v1')
#
#     if (add_nonce):
#         requestExtensions = tbsRequest.setComponentByName('requestExtensions').getComponentByName('requestExtensions')
#
#         extension = rfc2459.Extension()
#         extension.setComponentByName('extnID', rfc2560.id_pkix_ocsp_nonce)
#         extension.setComponentByName('critical', 0)
#
#         nonce = "0410EAE354B142FE6DE525BE7708307F80C2"
#         nonce = nonce[:-10] + str(int(time.time()))
#         ## ASN1: Tag (04: Integer) - Length (10:16 bytes) - Value  Encoding
#         ## See: http://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art062
#         ## current version of pyasn1_modules do not support nonce
#
#         extension.setComponentByName('extnValue', binascii.unhexlify(nonce))
#
#         requestExtensions.setComponentByPosition(0, extension)
#
#     requestList = tbsRequest.setComponentByName('requestList').getComponentByName('requestList')
#     requestList.setComponentByPosition(0, request)
#     return ocspRequest
#
#
# def return_ocsp_result(ocsp_response):
#     """ Extract the OCSP result from the provided ocsp_response """
#
#     try:
#         ocsp_response = ocsp.load_der_ocsp_response(ocsp_response.content)
#         # OCSP Response Status here:
#         # https://cryptography.io/en/latest/_modules/cryptography/x509/ocsp/#OCSPResponseStatus
#         # A status of 0 == OCSPResponseStatus.SUCCESSFUL
#         return ocsp_response
#
#     except ValueError as err:
#         return f"{str(err)}"
#
#
# def ocsp_crawler_v2(request):
#     r = redis.Redis(host='pharah.cs.vt.edu', port=6379, db=0, password="certificatesarealwaysmisissued")
#     ocsp_urls_set = r.smembers("ocsp:ocsp_urls")
#     ocsp_urls_lst = [item.decode() for item in ocsp_urls_set]
#
#     for ocsp_url in ocsp_urls_lst:
#         # if ocsp_url != "http://ocsp.comodoca.com" and ocsp_url != "http://ocsp.comodoca.com/":
#         #     continue
#
#         if not ocsp_url_db.objects.filter(url=ocsp_url).exists():
#             ocsp_url_instance = ocsp_url_db.objects.create(url=ocsp_url)
#             dns_records = get_dns_records(ocsp_url)
#             for record in dns_records:
#                 dns_record.objects.create(ocsp_url=ocsp_url_instance, type=record[0], record=record[1])
#         else:
#             ocsp_url_instance = ocsp_url_db.objects.get(url=ocsp_url)
#
#         q_key = "ocsp:serial:" + ocsp_url
#         elements = r.lrange(q_key, 0, -1)
#         elements = [e.decode() for e in elements]
#         elements = [elements[0]]
#         for element in elements:
#             try:
#                 serial_number, akid, fingerprint = element.split(":")
#                 # "ocsp:akid:" + akid
#                 ca_cert = fix_cert_indentation(r.get("ocsp:akid:" + akid).decode())
#
#                 file = open("OCSP_DNS_DJANGO/temp/{}.pem".format("key"), "w")
#                 file.write(ca_cert)
#                 file.close()
#
#
#
#                 ca_cert = pem.readPemFromString(ca_cert)
#                 issuerCert, _ = decoder.decode(ca_cert, asn1Spec=rfc2459.Certificate())
#
#                 ocsp_host = ocsp_url
#                 if ocsp_host.startswith("http://"):
#                     ocsp_host = ocsp_host[7:]
#                 if "/" in ocsp_host:
#                     ocsp_host = ocsp_host[0: ocsp_host.find("/")]
#
#                 request_cmd = 'ocsp -issuer OCSP_DNS_DJANGO/temp/{}.pem -serial '.format("key") + serial_number \
#                               + ' -url ' + ocsp_url + " -text -header host " + ocsp_host
#                 full_cmd = 'openssl' + " " + request_cmd
#
#                 out = subprocess.check_output(full_cmd, shell=True)
#                 out = out.decode()
#
#                 headers = {'Connection': 'Keep-Alive', \
#                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', \
#                            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:56.0) Gecko/20100101 Firefox/56.0", \
#                            'Content-Type': 'application/ocsp-request', \
#                            'Host': ocsp_host
#                            }
#                 import requests
#                 ocspReq = makeOcspRequest(issuerCert, hex(int(serial_number)), None, False)
#                 # import urllib3
#                 #
#                 # http = urllib3.PoolManager()
#                 #
#                 # req = http.request('POST', ocsp_url,
#                 #                  headers=headers,
#                 #                  body=encoder.encode(ocspReq))
#                 # response = req.read()
#                 #
#                 # a = 1
#                 import requests as r_req
#                 response = r_req.post(url=ocsp_url, data=encoder.encode(ocspReq), headers=headers, timeout=10)
#                 decoded_response = return_ocsp_result(response)
#
#
#                 if str(decoded_response.response_status) == "OCSPResponseStatus.SUCCESSFUL":
#                     print(ocsp_url, decoded_response.response_status)
#
#                 # label = str(random.randint(1, 100000))
#                 # file = open("OCSP_DNS_DJANGO/temp/{}.pem".format(label), "w")
#                 # file.write(ca_cert)
#                 # file.close()
#
#                 a = 1
#
#
#
#                 # https://serverfault.com/questions/466683/can-an-ssl-certificate-be-on-a-single-line-in-a-file-no-line-breaks
#                 # http://www.jfcarter.net/~jimc/documents/bugfix/21-openssl-ocsp.html
#                 # https://serverfault.com/questions/630975/ocsp-validation-unable-to-get-local-issuer-certificate
#
#                 # request_cmd = 'ocsp -issuer OCSP_DNS_DJANGO/temp/{}.pem -serial '.format(label) + serial_number \
#                 #               + ' -url ' + ocsp_url + " -text -header host " + ocsp_host
#                 # full_cmd = 'openssl' + " " + request_cmd
#                 #
#                 # out = subprocess.check_output(full_cmd, shell=True)
#                 # out = out.decode()
#
#                 # if "OCSP Response Status: successful" not in out:
#                 #     continue
#                 #
#                 # delegated_responder = False
#                 # if "Certificate:" in out and "X509v3 Extended Key Usage" in out and "OCSP Signing" in out:
#                 #     delegated_responder = True
#                 #
#                 # ocsp_data.objects.create(ocsp_url=ocsp_url_instance, serial=serial_number, akid=akid, fingerprint=fingerprint,
#                 #                          delegated_response=delegated_responder, ocsp_response=out)
#
#
#
#                 # print(delegated_responder)
#
#                 '''
#                     In my experience, one of the reasons you get an
#                     "unauthorized" response is when you ask the CA
#                     for the status of a certificate that it did not sign.
#                     In other words, a certificate signed by a different CA.
#                     In this case, the OCSP response is meant to indicate
#                     that it is not authorized to tell you whether the
#                     certificate is Good or Revoked.
#                 '''
#
#                 try:
#
#                     # os.remove("OCSP_DNS_DJANGO/temp/{}.pem".format(label))
#                     pass
#                 except OSError:
#                     pass
#
#             except Exception as e:
#                 print("Exception")
#
#     return HttpResponse("asdas")
