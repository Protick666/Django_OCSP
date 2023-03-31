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
    f = open("data/ttl_data_set-live-local-False.json")
    d = json.load(f)

    asn_set = set()
    for e in d:
        asn_set.add(e[0])

    # return list(asn_set)

    asn_to_cn = {}
    asn_to_addresses = {}

    lines = []
    for line in open('data/asns_full_info.json', 'r'):
        lines.append(json.loads(line))


    for a in lines:
        asn_to_cn[a['asn']] = a['country']['name']
        asn_to_addresses[a['asn']] = a['announcing']['numberAddresses']

    from collections import defaultdict
    cn_to_asn_list = defaultdict(lambda : list())

    for asn in asn_set:
        cn_to_asn_list[asn_to_cn[asn]].append((asn_to_addresses[asn], asn))

    for cn in cn_to_asn_list:
        cn_to_asn_list[cn].sort(reverse=True)

    ans_arr = []
    for cn in cn_to_asn_list:
        if len(cn) == 0:
            continue
        if len(cn_to_asn_list[cn]) < 500:
            ans_arr = ans_arr + cn_to_asn_list[cn]
        else:
            ans_arr = ans_arr + cn_to_asn_list[cn][: 500]

    ans_arr = [e[1] for e in ans_arr]
    return ans_arr


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