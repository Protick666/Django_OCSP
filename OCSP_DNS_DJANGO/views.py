

from django.http import HttpResponse

from OCSP_DNS_DJANGO.caching_strategy_master import ocsp_url_analizer
from OCSP_DNS_DJANGO.ip_to_resolver_mapper import luminati_ip_to_resolver
from OCSP_DNS_DJANGO.luminati_async_asn_v2 import luminati_master_crawler_async_v2
from OCSP_DNS_DJANGO.practise_ground.cache_exp_prac import  cache_exp_init_v7


def ocsp_crawler_v2(request):
    #cache_exp_init_v4()
    cache_exp_init_v7()
    #ocsp_url_analizer()
    return HttpResponse("asdas")

