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

def chunks(lst, n):
    ans = []
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        ans.append(lst[i:i + n])
    return ans


async def query_through_luminati(hop, session, target, mode):
    try:
        global meta_data

        import random, string, time
        letters = string.ascii_lowercase
        session_key = ''.join(random.choice(letters) for i in range(8)) + str(int(time.time()))

        asn = hop
        proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(asn, session_key)

        if mode == 'cdn':
            headers = [('User-Agent', 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')]
            async with session.get(url=target, proxy=proxy_url, headers=headers) as response:
                try:
                    # await response.text()
                    header_dict = dict(response.headers)
                    meta_data.append((hop, mode, target, header_dict, int(time.time())))

                except Exception as e:
                    pass
        elif mode == 'facebook':
            headers = [('Accept',
                        'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'),
                       ('User-Agent',
                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'),
                       ('Accept-Language', 'en-US,en;q=0.9')]
            async with session.get(url=target, proxy=proxy_url,headers=headers) as response:
                try:

                    # 23980
                    var = await response.text()
                    meta_data.append((hop, mode, target, var, int(time.time())))
                    a = 1
                except Exception as e:
                    pass
        elif mode == 'netflix':
            headers = [('User-Agent', 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')]
            async with session.get(url=target, proxy=proxy_url, headers=headers) as response:
                try:
                    var = await response.json()
                    meta_data.append((hop, mode, target, var, int(time.time())))
                    a = 1
                except Exception as e:
                    pass
    except Exception as e:
        pass


async def process_ocsp_urls_async(chosen_hop_list, target, mode):

    if mode == 'facebook':
        timeout = aiohttp.ClientTimeout(total=80)
    else:
        timeout = aiohttp.ClientTimeout(total=20)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for hop in chosen_hop_list:
            try:
                import random
                task = asyncio.ensure_future(
                    query_through_luminati(hop=hop, session=session, target=target, mode=mode))
                tasks.append(task)
            except Exception as e:
                pass
        execution_results = await asyncio.gather(*tasks)


def carry_out_exp(hops, url, mode):
    asyncio.run(process_ocsp_urls_async(chosen_hop_list=hops, target=url, mode=mode))


def luminati_asn_ttl_crawler_req(target, mode):

    chosen_hop_list = get_all_asns()

    hop_chunks = chunks(chosen_hop_list, 1000)


    for chunk in hop_chunks:
        carry_out_exp(hops=chunk, url=target, mode=mode)
        print("done with chunk {}".format(target))


if __name__ == "__main__":

    import json

    dump_path = "/net/data/net-neutrality/global-v1/"
    Path(dump_path).mkdir(parents=True, exist_ok=True)

    urls = get_urls()
    for url in urls:
        mode = None
        if 'facebook' in url.lower():
            mode = 'facebook'
        elif 'netflix' in url.lower():
            mode = 'netflix'
        else:
            mode = 'cdn'

        luminati_asn_ttl_crawler_req(target=url, mode=mode)
        print("done with {}".format(url))

        time_str = int(time.time())
        with open("{}{}.json".format(dump_path, time_str), "w") as ouf:
            json.dump(meta_data, fp=ouf)

        meta_data = []






