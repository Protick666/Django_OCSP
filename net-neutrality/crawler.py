import asyncio
import logging
from pathlib import Path
import aiohttp
import json
import time
from helpers import *
logger = logging.getLogger(__name__)

dict_of_phases = {}
meta_data = []


async def query_through_luminati(hop, session, target):
    try:
        global dict_of_phases
        global meta_data

        import random, string, time
        letters = string.ascii_lowercase
        session_key = ''.join(random.choice(letters) for i in range(8)) + str(int(time.time()))

        cn = hop
        proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(cn, session_key)

        async with session.get(url=target, proxy=proxy_url) as response:
            try:
                header_dict = dict(response.headers)
                meta_data.append((hop, target, header_dict, int(time.time())))
            except Exception as e:
                a = 1
                pass
    except Exception as e:
        a = 1
        pass


async def process_ocsp_urls_async(chosen_hop_list, target):

    timeout = aiohttp.ClientTimeout(total=100)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for hop in chosen_hop_list:
            try:
                import random
                task = asyncio.ensure_future(
                    query_through_luminati(hop=hop, session=session, target=target))
                tasks.append(task)
            except Exception as e:
                pass
        execution_results = await asyncio.gather(*tasks)


def carry_out_exp(hops, url):
    asyncio.run(process_ocsp_urls_async(chosen_hop_list=hops, target=url))


def choose_country_codes():
    f = open("countries.json")
    d = json.load(f)
    country_codes = []
    for e in d:
        cd = d[e]["cc"]
        for pp in range(10):
            country_codes.append(cd)
    return country_codes


def luminati_asn_ttl_crawler_req(target):
    #chosen_hop_list = choose_country_codes()
    chosen_hop_list = get_korea_asns()
    carry_out_exp(hops=chosen_hop_list, url=target)

    store_dict = {'meta_data': meta_data}
    import json

    time_str = int(time.time())
    dump_path = "/net/data/net-neutrality/korean-asns/"
    Path(dump_path).mkdir(parents=True, exist_ok=True)
    with open("{}{}.json".format(dump_path, time_str), "w") as ouf:
        json.dump(store_dict, fp=ouf)


# urls = ['https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=5',
#         'https://api.fast.com/netflix/speedtest/v2?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=5']
# dump_str = ['fast-api', 'fast-api']
# index = 1

while(True):
    urls = get_urls()

    for url in urls:
        luminati_asn_ttl_crawler_req(target=url)
        print("done with {}".format(url))

    time.sleep(15*60)

