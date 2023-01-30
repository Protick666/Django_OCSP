

def get_urls():
    file1 = open('data/urls', 'r')
    Lines = file1.readlines()
    url_list = []
    for line in Lines:
        url = "https://" + line.strip()
        url_list.append(url)
    return url_list


def get_korea_asns():
    file1 = open('data/korea', 'r')
    Lines = file1.readlines()
    asn_list = []
    for line in Lines:
        segments = line.split()
        asn = segments[0]
        asn_list.append(asn[2:])
    return asn_list