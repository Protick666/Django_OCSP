

from django.http import HttpResponse

from OCSP_DNS_DJANGO.luminati_async_asn import luminati_master_crawler_async
from OCSP_DNS_DJANGO.luminati_async_asn_weird import luminati_master_crawler_debug_now
from OCSP_DNS_DJANGO.luminati_sanity_checker import check_sanity
from OCSP_DNS_DJANGO.practise_ground.luminati_train_ground import luminati_master_crawler_debug


def ocsp_crawler_v2(request):
    check_sanity()
    return HttpResponse("asdas")

