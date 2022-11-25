from OCSP_DNS_DJANGO.loominati_helper_tools import get_ocsp_hosts_v2
from OCSP_DNS_DJANGO.models import *
from collections import defaultdict
import pyasn, json
from multiprocessing.dummy import Pool as ThreadPool
from OCSP_DNS_DJANGO.practise_ground.cache_exp_prac import *

# TODO check pyasn, intervaltree

# from caching_strategy_master_v2 import *

from OCSP_DNS_DJANGO.tools import get_dns_records, AS2ISP, get_base_url

asndb = pyasn.pyasn('OCSP_DNS_DJANGO/ipsan_db.dat')
as2isp = AS2ISP()

CDNS = ['Akamai',
        'Akadns'
        'Amazon',
        'Bitgravity',
        'Cachefly',
        'CDN77',
        'CDNetworks',
        'CDNify',
        'ChinaCache',
        'ChinaNetCenter',
        'EdgeCast',
        'Fastly',
        'Highwinds',
        'Internap',
        'KeyCDN',
        'Level3',
        'Limelight',
        'MaxCDN',
        'NetDNA',
        'Telefónica',
        'XCDN',
        'CloudFlare',
        'Jetpack',
        'Rackspac',
        'CloudLayer',
        'CloudCache',
        'TinyCDN',
        'Amazon',
        'Incapsula',
        'jsDelivr',
        'EdgeCast',
        'CDNsun',
        'Limelight',
        'Azure',
        'CDNlio',
        'SoftLayer',
        'ITWorks',
        'CloudOY',
        'Octoshape',
        'Hibernia',
        'WebMobi',
        'CDNvideo']

url_to_a_record = {}

def get_dns_records_of_ocsp_hosts():
    d = defaultdict(lambda : dict())
    ocsp_hosts = get_ocsp_hosts_v2(redis_host=redis_host)
    print("Total urls from redis {}".format(len(ocsp_hosts)))

    for host in ocsp_hosts:
         try:
             dns_records = get_dns_records(ocsp_url=host)
             a_records = [e[1] for e in dns_records if e[0] == 'A_RECORD']
             c_names = [e[1] for e in dns_records if e[0] == 'CNAME']
             if not a_records:
                 continue
             d[host]['a_record'] = a_records[0]
             url_to_a_record[host] = a_records[0]
             if c_names:
                 d[host]['cname'] = c_names[0]
         except Exception as e:
            pass

    return d


def get_asn(ip):
    return asndb.lookup(ip)[0]


def get_org(asn):
    ans = str(as2isp.getISP("20221212", asn)[0])
    ans.replace("\"", "")
    return ans


def get_root_domain(url):
    if url.startswith("http://"):
        url = url[7:]
    if "/" in url:
        url = url[0: url.find("/")]
    return url


# in future, do all !!
def ocsp_url_analizer():
    d = get_dns_records_of_ocsp_hosts()
    base_url_vis = {}
    ans = {}

    count = 1

    tot_keys = len(list(d.keys()))

    for key in d:
        base_url = get_base_url(key)
        if base_url in base_url_vis:
            if len(ans[base_url]['host_list']) < 20:
                ans[base_url]['host_list'].append(key)
            # tot_count = OcspResponsesWrtAsn.objects.filter(ocsp_url__id=host_to_id[key]).count()
            # ans[base_url]['count'] += tot_count
            #print("Done with {")
            continue
        base_url_vis[base_url] = 1
        #print(base_url, "{}/{}".format(count, tot_keys))
        count += 1
        # a_record, cname
        d[key]['asn'] = get_asn(d[key]['a_record'])
        d[key]['org'] = get_org(d[key]['asn'])
        #d[key]['root_domain'] = get_root_domain(key)
        is_delegated = OcspResponsesWrtAsn.objects.filter(ocsp_url__url=key,
                                                          ocsp_response_status='OCSPResponseStatus.SUCCESSFUL',
                                                          ocsp_cert_status='OCSPCertStatus.GOOD').values('delegated_response').distinct()

        #tot_count = OcspResponsesWrtAsn.objects.filter(ocsp_url__id=host_to_id[key]).count()

        d[key]['is_delegated'] = list(is_delegated)
        ans[base_url] = d[key]
        ans[base_url]['host_list'] = [key]
        #ans[base_url]['count'] = int(tot_count)
        ans[base_url]["full_url"] = key
    # a = 1
    with open('data/ocsp_url_info_v3.json', "w") as ouf:
        json.dump(ans, fp=ouf)

    return ans

mother_dict = {}
ans_dict = {}


def exp_init(base_url):
    try:
        global mother_dict
        global ans_dict

        candidate_urls = mother_dict[base_url]['host_list']
        print("Chosen {} from {}".format(candidate_urls[0], base_url))
        # print(candidate_urls[0] in url_to_a_record)
        # print(url_to_a_record)
        base = get_base_url(candidate_urls[0])
        ans = luminati_master_crawler_cache(ocsp_url=candidate_urls[0], ip_host=mother_dict[base]['a_record'])
        # from caching_strategy_master_v2 import *
        # ans[base_url]['host_list'] = [(key, host_to_id[key])]
        # ans[base_url]['count'] = int(tot_count)
        # ans[base_url]["full_url"] = key

        ans_dict[base_url] = ans
        print("Done with {}".format(base_url))
    except Exception as e:
        print(base_url, e)
        ans_dict[base_url] = {}


def caching_exp():
    global mother_dict
    #d = ocsp_url_analizer()
    f = open('data/ocsp_url_info_v3.json')
    d = json.load(f)
    mother_dict = d

    base_urls = list(d.keys())[-4: ]
    print("10", base_urls)
    pool = ThreadPool(40)
    results = pool.map(exp_init, base_urls)
    pool.close()
    pool.join()

    with open('data/ult_mother.json', "w") as ouf:
        json.dump(ans_dict, fp=ouf)

    # # # # # # #
    ###base url###










caching_exp()
