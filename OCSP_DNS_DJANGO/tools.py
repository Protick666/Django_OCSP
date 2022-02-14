from dns import resolver, rdata
from dns.rdatatype import CNAME, A, NS
import time
from intervaltree import *
# import ujson as json
import json
from datetime import datetime
import os
import pathlib
import asyncio


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

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans



# TODO telegram check!!
import aiohttp
import logging
logger = logging.getLogger(__name__)

available_asns = []

async def query_through_luminati(hop, session):
    try:
        import random, string, time

        #session_key = ''.join(random.choice(letters) for i in range(5)) + str(int(time.time()))

        proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(hop)

        async with session.get(url='http://lumtest.com/myip.json', proxy=proxy_url) as response:
            try:
                # TODO check data
                result_data = await response.read()
                data = json.loads(result_data.decode("utf-8"))

                global available_asns
                available_asns.append(hop)

            except Exception as e:
                a = 1
                logger.error(
                    "Error in getting ip address through lumtest ({})".format(e))

    except Exception as e:
        pass

async def process_asn_chunks(chosen_hop_list):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for hop in chosen_hop_list:
            try:
                import random
                task = asyncio.ensure_future(
                    query_through_luminati(hop=hop[2:], session=session))
                tasks.append(task)
            except Exception as e:
                logger.error("Error in Processing hop {}: {}".format(hop, e))
        execution_results = await asyncio.gather(*tasks)


def get_all_active_asns():
    send_telegram_msg("Starting ASN crawling")
    import ujson
    f = open("AS_INFO.json")
    asn_info = ujson.load(f)

    import urllib.request

    asn_keys = list(asn_info.keys())

    asn_chunks = chunks(asn_keys, 500)

    counter = 0
    for chunk in asn_chunks:
        counter += 1
        asyncio.run(process_asn_chunks(chosen_hop_list=chunk))
        send_telegram_msg("Done with chunk {} out of chunks {}".format(counter, len(asn_chunks)))

    # counter = 0
    # for asn_key in asn_keys:
    #     counter += 1
    #     if counter % 1000 == 0:
    #         send_telegram_msg("ASN check done for {}".format(counter))
    #     try:
    #         asn = asn_key[2:]
    #         opener = urllib.request.build_opener(
    #             urllib.request.ProxyHandler(
    #                 {
    #                     'http': 'http://lum-customer-c_9c799542-zone-protick-asn-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(asn)}))
    #
    #         data = opener.open('http://lumtest.com/myip.json').read()
    #         data = json.loads(data.decode("utf-8"))
    #         available_asns.append(asn)
    #         # if int(asn) > 30:
    #         #     break
    #     except Exception as e:
    #         pass

    send_telegram_msg("Done with all the chunks")
    from datetime import date
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    d1 = d1.replace("/", "-")
    out_file = open("available_asns-{}.json".format(d1), "w")
    json.dump(available_asns, out_file)
    #print(len(available_asns))
    send_telegram_msg("Dumped the file!")


def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])
