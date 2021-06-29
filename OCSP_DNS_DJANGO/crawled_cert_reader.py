from OCSP_DNS_DJANGO.management.commands.scheduler import return_ocsp_result
from OCSP_DNS_DJANGO.models import OcspResponsesWrtAsn, ocsp_data_luminati

CDN_HINTS = ["Akam", "cloud", "edge", "fast", "tiny", 'CDN', 'DELIGATED', 'DELIGATE', 'Cloudfront', ]

CDNS = ['Akamai',
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

def find_all_relevant_strings(delegated_cert):
    relevant_strings = []
    relevant_strings.append(("subject", str(delegated_cert.subject).lower()))
    relevant_strings.append(("issuer", str(delegated_cert.issuer).lower()))
    e_count = 0
    for extension in delegated_cert.extensions._extensions:
        relevant_strings.append(("ex-{}".format(e_count), str(extension).lower()))
        e_count += 1
    return relevant_strings


from collections import defaultdict
def check_certs_for_strings():
    d = {}
    ans_dict_wrt_asn = defaultdict(lambda: list())
    response_db_id_to_string_dict = defaultdict(lambda: list())


    ocsp_responses_wrt_asns = OcspResponsesWrtAsn.objects.filter(delegated_response=True)
    for response in ocsp_responses_wrt_asns:
        if response.ocsp_url.url in d:
            continue

        delegated_response = return_ocsp_result(response.ocsp_response_as_bytes, is_bytes=True)
        d[response.ocsp_url.url] = 1
        delegated_cert = delegated_response.certificates[0]

        relevant_strings = find_all_relevant_strings(delegated_cert)

        for relevant_string in relevant_strings:
            for key in CDNS + CDN_HINTS:
                lower_key = key.lower()
                if lower_key in relevant_string[1]:
                    ans_dict_wrt_asn[key].append(response.id)
                    response_db_id_to_string_dict[response.id] = relevant_strings.copy()
    ######################################################################################
    a = 1
    ans_dict_wrt_asn = dict(sorted(ans_dict_wrt_asn.items(), key=lambda x: -len(x[1])))

    import json
    for key in ans_dict_wrt_asn:
        ans_dict_wrt_asn[key] = list(set(ans_dict_wrt_asn[key]))

    with open("ocsp_cert_string_search_results.json", "w") as ouf:
        json.dump(ans_dict_wrt_asn, fp=ouf)

    with open("ocsp_cert_db_id_to_string.json", "w") as ouf:
        json.dump(dict(response_db_id_to_string_dict), fp=ouf)










