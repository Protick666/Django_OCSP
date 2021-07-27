from dns import resolver, rdata
from dns.rdatatype import CNAME, A, NS
import time
from intervaltree import *
# import ujson as json
import json
from datetime import datetime
import os
import pathlib


class AS2ISP:
    def __init__(self):
        self.raw_path = "OCSP_DNS_DJANGO/" + "/data"
        self.export_path = "OCSP_DNS_DJANGO/" + "/data/as2isp.json"

        self.date = []
        self.intervalTree = IntervalTree()
        self.as2isp = None

        self.loadDate()
        # self.check_cumulative()
        # self.saveDB()
        self.loadDB()

    def loadDate(self):
        """
        for fname in os.listdir(self.raw_path):
            if("as-rel.txt" not in fname): continue
            date = fname.split(".")[0]
            self.date.append(date)
        """
        d = []
        for fname in os.listdir(self.raw_path):
            if ("as-org2info.txt" not in fname):
                continue
            date = fname.split(".")[0]
            d.append(date)

        d.append("21000000")

        d = sorted(d)
        for prev, next in zip(d[:-1], d[1:]):
            self.intervalTree[prev:next] = prev


    def loadDB(self):
        t = time.time()
        f = open(self.export_path)
        self.as2isp = json.load(f)
        print('as2ISP DB loaded done: it took %s secs' % (time.time() - t))


    def getISP(self, date, asnum):
        """
        dbdate = self.date[min(range(len(self.date)),
            key=lambda v: abs((datetime.strptime(self.date[v], "%Y%m%d") - datetime.strptime(date, "%Y%m%d")).days))]
        #print dbdate

        """
        if (date <= min(self.intervalTree)[0]):
            date = min(self.intervalTree)[0]

        # First day
        try:
            dbdate = list(self.intervalTree[date])[0][2]
            # print("Chosen date: {}".format(dbdate))
        except Exception as e:
            a = 1

        asnum = str(asnum)
        if asnum not in self.as2isp[dbdate]:
            return "None", "None"

        org, country = self.as2isp[dbdate][asnum]
        if (country == ""): country = 'None'
        if (org == ""): org = 'None'

        return org, country

    def check_cumulative(self):
        ORG_NAME = "format:org_id|changed|org_name|country|source"
        AS_ORG = "format:aut|changed|aut_name|org_id|source"
        AS_ORG_NEW = "format:aut|changed|aut_name|org_id|opaque_id|source"
        asnumDB = {}

        print("totol files: {}".format(list(os.listdir(self.raw_path))))
        l = 0
        files = sorted(os.listdir(self.raw_path))
        set_prev, current_set = set(), set()
        for fname in files:
            if ("as-org2info.txt" not in fname): continue
            date = fname.split(".")[0]
            print("Processing date {}".format(date))
            asnumDB[date] = {}
            org_id2name = {}
            as_asnum2name = {}

            line_type = 0
            for line in open(os.path.join(self.raw_path, fname)):
                if (ORG_NAME in line):
                    line_type = 1
                    continue

                elif (AS_ORG in line):
                    line_type = 2
                    continue

                elif (AS_ORG_NEW in line):
                    line_type = 3
                    continue

                if (line_type == 0):
                    continue

                if (line_type == 1):  ## ORG_NAME
                    org_id, changed, org_name, country, source = line.split("|")

                elif (line_type == 2):  ## AS_ORG
                    asnum, changed, aut_name, org_id, source = line.split("|")
                    current_set.add(asnum)

                elif (line_type == 3):  ## AS_ORG_NEW
                    asnum, changed, aut_name, org_id, opaque_id, source = line.split("|")
                    current_set.add(asnum)

            for prev_element in set_prev:
                if prev_element not in current_set:
                    print("Anomaly {}".format(prev_element))

            set_prev = current_set.copy()
            current_set = set()

            l += 1
            print("Processed {} files".format(l))




    def saveDB(self):
        ORG_NAME = "format:org_id|changed|org_name|country|source"
        AS_ORG = "format:aut|changed|aut_name|org_id|source"
        AS_ORG_NEW = "format:aut|changed|aut_name|org_id|opaque_id|source"
        asnumDB = {}

        print("totol files: {}".format(list(os.listdir(self.raw_path))))
        l = 0
        for fname in os.listdir(self.raw_path):
            if ("as-org2info.txt" not in fname): continue
            date = fname.split(".")[0]
            asnumDB[date] = {}
            org_id2name = {}
            as_asnum2name = {}

            line_type = 0
            for line in open(os.path.join(self.raw_path, fname)):
                if (ORG_NAME in line):
                    line_type = 1
                    continue

                elif (AS_ORG in line):
                    line_type = 2
                    continue

                elif (AS_ORG_NEW in line):
                    line_type = 3
                    continue

                if (line_type == 0):
                    continue

                if (line_type == 1):  ## ORG_NAME
                    org_id, changed, org_name, country, source = line.split("|")
                    # org_id2name[org_id] = (org_name.encode('utf-8'), country.encode('utf-8'))
                    org_id2name[org_id] = (org_name, country)

                elif (line_type == 2):  ## AS_ORG
                    asnum, changed, aut_name, org_id, source = line.split("|")
                    asnumDB[date][asnum] = org_id2name[org_id]

                elif (line_type == 3):  ## AS_ORG_NEW
                    asnum, changed, aut_name, org_id, opaque_id, source = line.split("|")
                    asnumDB[date][asnum] = org_id2name[org_id]

            l += 1

            print("Processed {} files".format(l))
        # json.dumps(asnumDB, open(self.export_path, "w"))

        with open(self.export_path, "w") as ouf:
            json.dump(asnumDB, fp=ouf)





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
        for rdata in resolver.resolve(ocsp_url_base, NS, raise_on_no_answer=False):
            dns_records.append(('NS_RECORD', str(rdata)))
        return dns_records
    except Exception as e:
        return []


def get_ns_records(ocsp_url):
    try:
        dns_records = []
        if ocsp_url.startswith("http://"):
            ocsp_url_base = ocsp_url[7:]
        if "/" in ocsp_url_base:
            ocsp_url_base = ocsp_url_base[0: ocsp_url_base.find("/")]
        for rdata in resolver.resolve(ocsp_url_base, NS, raise_on_no_answer=False):
            dns_records.append(('NS_RECORD', str(rdata)))
        return dns_records
    except Exception as e:
        return []

