import json


def get_urls():
    file1 = open('data/urls', 'r')
    Lines = file1.readlines()
    url_list = []
    for line in Lines:
        url = "https://" + line.strip()
        url_list.append(url)
    return url_list


def get_all_asns():
    lines = []
    for line in open('data/asns_full_info.json', 'r'):
        lines.append(json.loads(line))

    tot_set = set()
    filled_set = set()
    overall_country = set()
    filled_country = set()

    for a in lines:
        tot_set.add(a['asn'])
        overall_country.add(a['country']['name'])
        if a['announcing']['numberPrefixes'] > 0:
            filled_set.add(a['asn'])
            filled_country.add(a['country']['name'])

    return list(tot_set)

def get_korea_asns():
    file1 = open('data/korea', 'r')
    Lines = file1.readlines()
    asn_list = []
    for line in Lines:
        segments = line.split()
        asn = segments[0]
        asn_list.append(asn[2:])
    return asn_list


def get_korea_asn_to_org():
    d = {}
    file1 = open('data/korea', 'r')
    Lines = file1.readlines()
    asn_list = []
    for line in Lines:
        segments = line.split()
        asn = segments[0][2:]
        names = line.split()[1: -1]
        s = ""
        for e in names:
            s = s + e + " "
        d[asn] = s
    return d

a = get_korea_asn_to_org()