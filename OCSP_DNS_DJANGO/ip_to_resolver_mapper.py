import asyncio
import logging
import time

import aiohttp
import django
import redis

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import get_total_cert_per_ocsp_url, \
    choose_hops, choose_all_available_asns

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
password = "G$!vz?Ap@?T=4k7E"


TOTAL_CERTS = get_total_cert_per_ocsp_url()

# 612 ASNs
# 109 countries
import random
import uuid

# /var/log/apache2/access.log apache
# /var/log/bind/query.log bind



async def query_through_luminati(session, hop):
    try:
        proxy_url = 'http://lum-customer-c_9c799542-zone-residential-asn-{}:xm4jk9845cgb@zproxy.lum-superproxy.io:22225'.format(hop)

        identifier = str(uuid.uuid4()).replace("-", "") + str(int(time.time())) + "-" + str(hop) + "-" + EXPERIMENT_IDENTIFIER
        url = "http://" + "{}.luminati.netsecurelab.org".format(identifier)

        async with session.get(url=url, proxy=proxy_url) as response:
            result_data = await response.read()

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


def chunkify(lst, per_chink_len):
    mother_list = []
    index = 0
    while index < len(lst):
        mother_list.append(lst[index: index + per_chink_len])
        index += per_chink_len
    return mother_list


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
    for i in range(6):
        starting_time = time.time()

        logger.info("Starting ip to resolver crawler job now !")

        chosen_hop_list = choose_all_available_asns()
        PER_CHUNK_ASN = 1000
        hop_chunks = chunkify(lst=chosen_hop_list, per_chink_len=PER_CHUNK_ASN)

        logger.info("Chosen total {} hops".format(len(chosen_hop_list)))

        for chunk in hop_chunks:
            asyncio.run(run_crawler(chosen_hop_list=chunk))

        elapsed_time = time.time() - starting_time
        print("Elapsed time {}".format(elapsed_time))
        send_telegram_msg(elapsed_time=elapsed_time)


def send_telegram_msg(elapsed_time):
    import telegram_send
    msg = "Ip to resolver crawling done, elapsed time {}".format(elapsed_time)
    telegram_send.send(messages=[msg])
