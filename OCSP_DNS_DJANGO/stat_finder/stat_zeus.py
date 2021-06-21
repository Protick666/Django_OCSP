import json


def find_cname(url, dns_records):
    # dns {'url': 'http://xnetcas2.ocsp.secomtrust.net', 'type': 'CNAME', 'record': 'ksdc0016-ocsp1.dr.secomtrust.net.'}
    for element in dns_records:
        if element['url'] == url and element['type'] == 'CNAME':
            return element['record']



def find_Arecord(url, dns_records):
    # dns {'url': 'http://xnetcas2.ocsp.secomtrust.net', 'type': 'CNAME', 'record': 'ksdc0016-ocsp1.dr.secomtrust.net.'}
    ans = []
    for element in dns_records:
        if element['url'] == url and element['type'] == 'A_RECORD':
            ans.append(element['record'])

    return ans


def ocsp_crawler_hosting_provider():
    f = open("OCSP_DNS_DJANGO/stat_finder/cn_dy.json")
    delegated_and_not_cname = json.load(f)
    delegated_and_not_cname = [x['url'] for x in delegated_and_not_cname]

    f = open("OCSP_DNS_DJANGO/stat_finder/dns.json")
    dns_records = json.load(f)

    d = {}
    for element in delegated_and_not_cname:
        url = element
        a_records = find_Arecord(url, dns_records)
        d[element] = a_records

    with open("ocsp_remote.json", "w") as ouf:
        json.dump(d, fp=ouf, indent=2)


def ocsp_crawler_find_stat():
    ## Classify top 30

    f = open("OCSP_DNS_DJANGO/stat_finder/top_30_ocsp_responders.json")
    top_responders = json.load(f)

    f = open("OCSP_DNS_DJANGO/stat_finder/dns.json")
    dns_records = json.load(f)

    f = open("OCSP_DNS_DJANGO/stat_finder/dy.json")
    delegated = json.load(f)
    delegated = [x['url'] for x in delegated]

    f = open("OCSP_DNS_DJANGO/stat_finder/cy_dy.json")
    delegated_and_cname = json.load(f)
    delegated_and_cname = [x['url'] for x in delegated_and_cname]

    f = open("OCSP_DNS_DJANGO/stat_finder/cy_dn.json")
    cname_and_not_delegated = json.load(f)
    cname_and_not_delegated = [x['url'] for x in cname_and_not_delegated]

    f = open("OCSP_DNS_DJANGO/stat_finder/cn_dy.json")
    delegated_and_not_cname = json.load(f)
    delegated_and_not_cname = [x['url'] for x in delegated_and_not_cname]

    # top_res {'url': 'http://ocsp.comodoca.com', 'total_ocsp_response': 191156}
    # dns {'url': 'http://xnetcas2.ocsp.secomtrust.net', 'type': 'CNAME', 'record': 'ksdc0016-ocsp1.dr.secomtrust.net.'}

    mother_dict = {}
    delegated_count, delegated_with_cname_count, delegated_without_cname_count, \
    non_delegated_with_cname_count,  non_delegated_without_cname_count = 0, 0, 0, 0, 0
    for element in top_responders:
        url = element['url']
        per_element_dict = {}
        per_element_dict['total_certs_crawled'] = element['total_ocsp_response']

        is_delegated = url in delegated
        per_element_dict['is_delegated'] = is_delegated

        cname = None
        if is_delegated:
            if url in delegated_and_cname:
                cname = find_cname(url, dns_records)
        else:
            if url in cname_and_not_delegated:
                cname = find_cname(url, dns_records)
        if cname:
            per_element_dict['cname'] = cname

        if is_delegated:
            delegated_count += 1
            if cname:
                delegated_with_cname_count += 1
            else:
                delegated_without_cname_count += 1
        else:
            if cname:
                non_delegated_with_cname_count += 1
            else:
                non_delegated_without_cname_count += 1

        mother_dict[url] = per_element_dict

    ans_dict = {}
    ans_dict['top_30_ocsp_responders'] = mother_dict
    ans_dict['delegated_count'] = delegated_count

    ans_dict['delegated_with_cname_count'] = delegated_with_cname_count
    ans_dict['delegated_without_cname_count'] = delegated_without_cname_count

    ans_dict['non_delegated_with_cname_count'] = non_delegated_with_cname_count
    ans_dict['non_delegated_without_cname_count'] = non_delegated_without_cname_count


    with open("ocsp_top_30.json", "w") as ouf:
        json.dump(ans_dict, fp=ouf, indent=2)












