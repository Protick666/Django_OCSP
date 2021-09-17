

from django.http import HttpResponse

from OCSP_DNS_DJANGO.caching_strategy_master import ocsp_url_analizer
from OCSP_DNS_DJANGO.ip_to_resolver_mapper import luminati_ip_to_resolver
from OCSP_DNS_DJANGO.luminati_async_asn_v2 import luminati_master_crawler_async_v2
from OCSP_DNS_DJANGO.luminati_parser import luminati_parser, get_objective_rate, get_latency_dist
from OCSP_DNS_DJANGO.practise_ground.cache_exp_prac import  cache_exp_init_v7


def ocsp_crawler_v2(request):
    #cache_exp_init_v4()
    #get_objective_rate('timeout_count', 40)
    get_latency_dist()
    #ocsp_url_analizer()
    return HttpResponse("asdas")

