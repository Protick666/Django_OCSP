from dns import resolver, rdata
from dns.rdatatype import CNAME, A

def fix_cert_indentation(der_encoded_cert):
    l = len(der_encoded_cert)
    index = 0
    ultimate = "-----BEGIN CERTIFICATE-----\n"
    while index < l:
        ultimate = ultimate + der_encoded_cert[index: index + 64] + "\n"
        index += 64
    ultimate = ultimate + "-----END CERTIFICATE-----"
    return ultimate


def get_dns_records(ocsp_url):
    try:
        dns_records = []
        if ocsp_url.startswith("http://"):
            ocsp_url_base = ocsp_url[7:]
        if "/" in ocsp_url_base:
            ocsp_url_base = ocsp_url_base[0: ocsp_url_base.find("/")]
        for rdata in resolver.resolve(ocsp_url_base, CNAME, raise_on_no_answer=False):
            dns_records.append(('CNAME', str(rdata)))
        for rdata in resolver.resolve(ocsp_url_base, A, raise_on_no_answer=False):
            dns_records.append(('A_RECORD', str(rdata)))
        return dns_records
    except Exception as e:
        return []