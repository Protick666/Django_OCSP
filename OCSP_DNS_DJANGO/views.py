

from django.http import HttpResponse

from OCSP_DNS_DJANGO.luminati_async_asn import luminati_master_crawler_async
from OCSP_DNS_DJANGO.luminati_sanity_checker import check_sanity


def ocsp_crawler_v2(request):
    # check_sanity()
    return HttpResponse("asdas")

