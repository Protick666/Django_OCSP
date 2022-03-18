import json
import pyasn
from OCSP_DNS_DJANGO.tools import get_dns_records, AS2ISP
from collections import defaultdict
from tabulate import tabulate
from OCSP_DNS_DJANGO.local import  LOCAL

if LOCAL:
    asndb = pyasn.pyasn('../OCSP_DNS_DJANGO/ipsan_db.dat')
else:
    asndb = pyasn.pyasn('OCSP_DNS_DJANGO/ipsan_db.dat')

as2isp = AS2ISP()


def get_asn(ip):
    return asndb.lookup(ip)[0]


def get_org(asn):
    org = str(as2isp.getISP("20221212", asn)[0])
    cntry = str(as2isp.getISP("20221212", asn)[1])
    org.replace("\"", "")
    cntry.replace("\"", "")
    return org, cntry


def test():
    f = open("../ttl_exp_asn_list.json")
    d = json.load(f)

    for e in d:
        print(get_org(e))


def table_maker():
    # k = {}
    # k['ic_ans_lst'] = ans_lst
    # k['c_ans_lst'] = c_ans_lst
    # with open("table_data.json", "w") as ouf:
    #     json.dump(k, fp=ouf)

    f = open("../table_data.json")
    d = json.load(f)
    ans_lst = d['ic_ans_lst']
    c_ans_lst = d['c_ans_lst']
    ans_lst.sort(key=lambda x: x[0], reverse=True)
    c_ans_lst.sort(key=lambda x: x[0], reverse=True)
    a = 1

    table_1 = [['Country', 'Org/ISP', 'Incorrect Resolvers', 'Exit nodes', 'Correct Resolvers']]
    for i in range(20):
        a = [ans_lst[i][3], ans_lst[i][2], ans_lst[i][0], ans_lst[i][1], ans_lst[i][4]]
        table_1.append(a)
    print(tabulate(table_1, headers='firstrow', tablefmt='fancy_grid'))

    table_2 = [['Country', 'Org/ISP', 'Correct Resolvers', 'Exit nodes', 'Incorrect Resolvers']]
    for i in range(20):
        a = [c_ans_lst[i][3], c_ans_lst[i][2], c_ans_lst[i][0], c_ans_lst[i][1], c_ans_lst[i][4]]
        table_2.append(a)
    print(tabulate(table_2, headers='firstrow', tablefmt='fancy_grid'))


def table_maker_preprocess():
    ans = defaultdict(lambda: [0, set()])
    c_ans = defaultdict(lambda: [0, set()])
    f = open("final_data.json")
    d = json.load(f)
    final_dict = d["data_elaborate"]
    print(d["Total_resolvers"])
    cn = {}
    # cnt, tot = 0, 0
    for key in final_dict:
        correct_set = set()
        incorrect_set = set()
        for e in final_dict[key]["ic"]:
            incorrect_set.add(e[1])
        for e in final_dict[key]["c"]:
            correct_set.add(e[1])
        total = len(correct_set) + len(incorrect_set)
        total_set = correct_set.union(incorrect_set)
        if total < 5:
            continue
        ratio = len(incorrect_set) / total
        if ratio >= .95:
            asn = get_asn(key)
            org, cntry = get_org(asn)
            ans[org][0] += 1
            ans[org][1].update(total_set)
            cn[org] = cntry
        elif ratio <= .05:
            asn = get_asn(key)
            org, cntry = get_org(asn)
            c_ans[org][0] += 1
            c_ans[org][1].update(total_set)
            cn[org] = cntry

    ans_lst = []
    c_ans_lst = []
    l = 0
    for key in ans:
        l += ans[key][0]
        correct_count = 0
        if key in c_ans:
            correct_count = c_ans[key][0]
        ans_lst.append((ans[key][0], len(ans[key][1]), key, cn[key], correct_count))
                        # resolver count, exit node count, isp, cntry

    for key in c_ans:
        l += c_ans[key][0]
        in_correct_count = 0
        if key in ans:
            in_correct_count = ans[key][0]
        c_ans_lst.append((c_ans[key][0],  len(c_ans[key][1]), key, cn[key], in_correct_count))

    k = {}
    k['ic_ans_lst'] = ans_lst
    k['c_ans_lst'] = c_ans_lst
    with open("table_data.json", "w") as ouf:
        json.dump(k, fp=ouf)


    # with open("isp_table.json", "w") as ouf:
    #     json.dump(ans_lst, fp=ouf)


def local_public_analyzer():

    f = open("final_resolver_to_asn.json")
    d = json.load(f)
    resolver_to_asns = d['resolver_to_asns']
    resolver_to_asn_own = d['resolver_to_asn_own']
    resolver_to_org_country = {}
    is_resolver_public = {}
    local_count, public_count = 0, 0
    for resolver in resolver_to_asns:
        ip_list = resolver_to_asns[resolver]
        org_set = set()
        cntry_set = set()

        resolver_asn = resolver_to_asn_own[resolver]
        res_org, cntry = get_org(resolver_asn)
        resolver_to_org_country[resolver] = (res_org, cntry)

        for ip_tuple in ip_list:
            asn = ip_tuple[1]
            org, cntry = get_org(asn)
            org_set.add(org)
            cntry_set.add(cntry)

        if len(cntry_set) > 1:
            is_resolver_public[resolver] = True
            public_count += 1
        elif len(org_set) == 1 and list(org_set)[0] == res_org:
            local_count += 1
            is_resolver_public[resolver] = False

    print("Total " , len(list(resolver_to_asns.keys())))
    print("Public " , public_count)
    print("Local " , local_count)

    with open("resolver_public_local_dict.json", "w") as ouf:
        json.dump(is_resolver_public, fp=ouf)

    with open("resolver_to_org_country.json", "w") as ouf:
        json.dump(resolver_to_org_country, fp=ouf)


#table_maker()
# test()


def reolver_hits_weird_cases():
    f = open("../req_id_to_bind_ips_phase_2.json")
    d = json.load(f)

    ip_to_count = defaultdict(lambda: 0)
    for e in d:
        if len(d[e]) > 100:
            for element in d[e]:
                ip_to_count[element] += 1

    ans = []
    for key in ip_to_count:
        ans.append((key, ip_to_count[key]))
    ans.sort(key=lambda x: -x[1])

    with open("recurrent_phase_2_ips.json", "w") as ouf:
        json.dump(ans, fp=ouf)

# reolver_hits_weird_cases()

def init():
    local_public_analyzer()
    table_maker_preprocess()

# table_maker()


