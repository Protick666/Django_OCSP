import json
f = open("data/rules.json")
rules = json.load(f)

def process_basics(arr):
    ans = []
    for e in arr:
        ans.append(e.split("-")[1][: 3])
    return ans

def process_dots(arr):
    ans = []
    for e in arr:
        ans.append(e.split(".")[1][1: 4])
    return ans

def get_files_from_dir(path):
    from os import listdir
    from os.path import isfile, join
    files = [path + f for f in listdir(path) if isfile(join(path, f))]
    return files

def find_tata_iata(str):
    return str[-4: -1]


class CDNSigPro:
    def extract_loc(self, data, url):
        try:
            if 'cloudflare' in url:
                str = data['CF-Ray']
                return str.split("-")[1].lower(), 'iata'
            if 'cdn77' in url:
                str = data['X-77-POP']
                return str, 'city'
            if 'gcore' in url:
                str = data['X-ID'].split("-")[0]
                if str in rules['x-id'][0]['hints']:
                    return rules['x-id'][0]['hints'][str], 'city'
                return None, None
            if 'cachefly' in url:
                str = data['X-CF1'].split(".")[-1].split("-")[0][: -1]
                return str, 'iata'
            if 'fastly' in url:
                str = data['X-Served-By'].split("-")[-1]
                return str, 'iata'
            if 'keycdn' in url:
                str = data['X-Edge-Location']
                return str, 'city'
            # "1675385726.cds201.sl1.hn,1675385726.cds240.sl1.c"
            if 'stackpath' in url:
                str = data['X-HW'].split(",")[0].split(".")[2][:2]
                if str in rules['x-hw'][0]['hints']:
                    return rules['x-hw'][0]['hints'][str], 'city'
                return None, None
            import re
            if 'tatacommunications' in url:
                str = data['X-Cache']
                iata = find_tata_iata(str)
                return iata, 'iata'

            if 'amazon' in url:
                str = data['X-Amz-Cf-Pop'][0: 3]
                return str, 'iata'

            if 'facebook' in url:
                video_re = "video\-[a-zA-Z]{3}\d\-\d\.[a-z]{2}\.fbcdn\.net"
                video_re_dot = "video\.f[a-zA-Z]{3}\d\-\d\.fna"

                video_basics = re.findall(video_re, data)
                video_dots = re.findall(video_re_dot, data)
                basic_iatas = process_basics(video_basics)
                basic_iata_set = set(basic_iatas)
                dot_iatas = process_dots(video_dots)
                dot_iatas_set = set(dot_iatas)
                total_iata_set = set(basic_iata_set).union(set(dot_iatas_set))
                return list(total_iata_set)[0], 'iata'

            if 'netflix' in url:
                return data['targets'][0]['url'].split("-")[2][: 3], 'iata'

            return None, None
        except Exception as e:
            return None, None

    def analyze_tuple(self,  tuple):
        asn, mode, url, data, _ = tuple
        return asn, url, self.extract_loc(data, url)






cdn_sig_pro = CDNSigPro()

data_arr = []
files = get_files_from_dir("/net/data/net-neutrality/global-v1/")
for file in files:
    f = open(file)
    d = json.load(f)
    data_arr = data_arr + d

from collections import defaultdict
url_to_asn_loc_tuple = defaultdict(lambda : list())


for element in data_arr:
    # asn, mode, url, data, _ = tuple
    # asn, url, (loc, loc_type)
    extracted_data = cdn_sig_pro.analyze_tuple(element)
    asn, url, loc_tuple = extracted_data
    loc, loc_type = loc_tuple
    if loc:
        url_to_asn_loc_tuple[url].append((asn, loc_tuple))

with open("url_to_asn_loc_tuple.json", "w") as ouf:
    json.dump(url_to_asn_loc_tuple, fp=ouf)