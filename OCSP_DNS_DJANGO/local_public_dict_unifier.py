import json

ttl_list = [5, 15, 30]

data_dir = "/home/protick/ocsp_dns_django/ttl_result_v2/"

master_dict = {}

def print_public_len(data):
    a = []
    for key in data:
        if data[key] is True:
            a .append(key)
    print("Total public ", len(a))


for ttl in ttl_list:
    file = "/home/protick/ocsp_dns_django/ttl_result_v2/" + str(ttl) + "/resolver_public_local_dict.json"
    f = open(file)
    d = json.load(f)
    print("Total {}".format(ttl), len(d.keys()))
    print_public_len(d)
    for key in d:
        # if key in master_dict:
        #     if master_dict[key] != d[key]:
        #         print("** Contradict ** ", key)
        master_dict[key] = d[key]

print("Total ", len(master_dict.keys()))
print_public_len(master_dict)

public_asn_list = []
for key in master_dict:
    if master_dict[key] is True:
        public_asn_list.append(key)

with open("{}{}".format(data_dir, "public_resolver_all.json"), "w") as ouf:
    json.dump(public_asn_list, fp=ouf)



