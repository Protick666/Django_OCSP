import asyncio
import logging
import time

import aiohttp
import django
import redis

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import get_total_cert_per_ocsp_url, \
    choose_hops

django.setup()

logger = logging.getLogger(__name__)


if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

r = redis.Redis(host=redis_host, port=6379, db=0,
                password="certificatesarealwaysmisissued")


# https://bgp.potaroo.net/cidr/autnums.html
# https://en.wikipedia.org/wiki/ISO_3166-2

EXPERIMENT_IDENTIFIER = "ip_to_resolver"


TOTAL_CERTS = get_total_cert_per_ocsp_url()

# 612 ASNs
# 109 countries
import random
import uuid

# /var/log/apache2/access.log



async def query_through_luminati(session, hop):
    try:
        #print("here")
        proxy_url = 'http://lum-customer-c_9c799542-zone-residential-asn-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(hop[0])

        identifier = str(uuid.uuid4()).replace("-", "") + str(int(time.time())) + "-" + EXPERIMENT_IDENTIFIER
        url = "http://" + "{}.luminati.netsecurelab.org".format(identifier)

        #url = 'https://www.googleapis.com/youtube/v3/channels?part=contentDetails&mine=true'

        #print(session)

        async with session.get(url=url, proxy=proxy_url) as response:
            #print(response)
            result_data = await response.read()

            #print(result_data.decode())
            headers = response.headers


            per_req_dict = {}
            for header in headers.keys():
                if header.startswith('x-luminati'):
                    per_req_dict[header] = headers[header]

            if response.status == 200:
                print("Requesting: {} through {}".format(url, hop))


    except Exception as e:
        print(e)



def initiate_query_through_luminati(session, hop, tasks):
    task = asyncio.ensure_future(query_through_luminati(session=session, hop=hop))
    tasks.append(task)


async def run_crawler(chosen_hop_list):
    #timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession() as session:
        tasks = []

        for hop in chosen_hop_list:
            try:
                initiate_query_through_luminati(session=session, hop=hop, tasks=tasks)
            except Exception as e:
                logger.error("Error in querying asn  {} ({})".format(hop, e))

        execution_results = await asyncio.gather(*tasks)


def luminati_ip_to_resolver():
    starting_time = time.time()

    logger.info("Starting ip to resolver crawler job now !")

    ban_list = []
    chosen_hop_list = choose_hops(only_asns=True, ban_list=[])
    chosen_hop_list = random.sample(chosen_hop_list, 20)


    logger.info("Chosen total {} hops".format(len(chosen_hop_list)))


    asyncio.run(run_crawler(chosen_hop_list=chosen_hop_list))

    elapsed_time = time.time() - starting_time
    print("Elapsed time {}".format(elapsed_time))
    #send_telegram_msg(elapsed_time=elapsed_time)


def send_telegram_msg(elapsed_time):
    import telegram_send
    msg = "Ip to resolver crawling done, elapsed time {}".format(elapsed_time)
    telegram_send.send(messages=[msg])


# async def main():
#     ban_list = []
#     chosen_hop_list = choose_hops(only_asns=True, ban_list=[])
#     chosen_hop_list = random.sample(chosen_hop_list, 10)
#
#     async with aiohttp.ClientSession() as session:
#         for hop in chosen_hop_list:
#             proxy_url = 'http://lum-customer-c_9c799542-zone-residential-asn-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(
#                 hop[0])
#
#             identifier = str(uuid.uuid4()).replace("-", "") + str(int(time.time())) + "-" + EXPERIMENT_IDENTIFIER
#             url = "{}-luminati.netsecurelab.org".format(identifier)
#             async with session.get(url=url, proxy=proxy_url) as resp:
#                 print(resp.status)
#                 print(await resp.text())
#
#
# loop = asyncio.get_event_loop()
# loop.run_until_complete(main())
