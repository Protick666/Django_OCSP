from OCSP_DNS_DJANGO.loominati_helper_tools import get_ocsp_hosts
from OCSP_DNS_DJANGO.models import *
from collections import defaultdict
import pyasn, json

# TODO check pyasn, intervaltree

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

def get_dns_records_of_ocsp_hosts():
    d = defaultdict(lambda : dict())
    ocsp_hosts = get_ocsp_hosts()
    for host in ocsp_hosts:
         try:
             dns_records = get_dns_records(ocsp_url=host)
             a_records = [e[1] for e in dns_records if e[0] == 'A_RECORD']
             c_names = [e[1] for e in dns_records if e[0] == 'CNAME']
             if not a_records:
                 continue
             d[host]['a_record'] = a_records[0]
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

def ocsp_url_analizer():
    d = get_dns_records_of_ocsp_hosts()

    base_url_vis = {}
    ans = {}

    count = 1
    for key in d:
        base_url = get_base_url(key)
        if base_url in base_url_vis:
            continue
        base_url_vis[base_url] = 1
        print(base_url, count)
        count += 1
        # a_record, cname
        d[key]['asn'] = get_asn(d[key]['a_record'])
        d[key]['org'] = get_org(d[key]['asn'])
        #d[key]['root_domain'] = get_root_domain(key)
        is_delegated = OcspResponsesWrtAsn.objects.filter(ocsp_url__url=key,
                                                          ocsp_response_status='OCSPResponseStatus.SUCCESSFUL',
                                                          ocsp_cert_status='OCSPCertStatus.GOOD').values('delegated_response').distinct()
        d[key]['is_delegated'] = list(is_delegated)
        ans[base_url] = d[key]
        ans[base_url]["full_url"] = key
    # a = 1
    with open('data/ocsp_url_info_v2.json', "w") as ouf:
        json.dump(ans, fp=ouf)






