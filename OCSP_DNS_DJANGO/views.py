

from django.http import HttpResponse

from OCSP_DNS_DJANGO.crawled_cert_reader import check_certs_for_strings, check_certs_for_strings_v2
from OCSP_DNS_DJANGO.latency_maker import find_latency
from OCSP_DNS_DJANGO.luminati_async_asn import luminati_master_crawler_async
from OCSP_DNS_DJANGO.luminati_async_asn_weird import luminati_master_crawler_debug_now
from OCSP_DNS_DJANGO.luminati_sanity_checker import check_sanity
from OCSP_DNS_DJANGO.practise_ground.luminati_train_ground import luminati_master_crawler_debug


def ocsp_crawler_v2(request):
    check_certs_for_strings_v2()
    return HttpResponse("asdas")

