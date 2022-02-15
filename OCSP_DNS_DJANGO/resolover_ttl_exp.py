import asyncio
import json
import logging
import time

import aiohttp
import django
import redis
from channels.db import database_sync_to_async
from pyasn1.codec.der import encoder

from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import get_total_cert_per_ocsp_url, \
    choose_hops_for_ttl_exp
from OCSP_DNS_DJANGO.management.commands.scheduler import return_ocsp_result
from OCSP_DNS_DJANGO.models import *
from OCSP_DNS_DJANGO.tools import chunks

django.setup()

logger = logging.getLogger(__name__)

QUERY_URL = 'ttlexp.luminati.netsecurelab.org'

HOST_DICT = {
    "first": 1,
    "second": 2
}

# 52.44.221.99 -> phase1
# 3.220.52.113 -> phase 2

if LOCAL:
    redis_host = LOCAL_REDIS_HOST
else:
    redis_host = REMOTE_REDIS_HOST

TOTAL_CERTS = get_total_cert_per_ocsp_url()


store_tuples = []

# TODO check telegram

def check_host(result_data):
    str = result_data.decode("utf-8")
    if 'phase1' in str:
        return 1
    elif 'phase2' in str:
        return 2
    raise Exception



async def query_through_luminati(hop, session, exp_id, phase):
    try:
        import random, string, time
        letters = string.ascii_lowercase
        session_key = ''.join(random.choice(letters) for i in range(5)) + str(int(time.time()))

        resolution_data = [phase, hop, exp_id]

        if phase == 1:
            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(hop)
        elif phase == 2:
            proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(
                hop, session_key)
        print("here")
        if phase == 2:
            url_rand = ''.join(random.choice(letters) for i in range(5)) + str(int(time.time()))
            async with session.get(url='http://{}.{}.{}'.format(exp_id, url_rand, QUERY_URL), proxy=proxy_url) as response:
                try:
                    print("there")
                    result_data = await response.read()
                    which_host = check_host(result_data)
                    resolution_data.append(which_host)
                    resolution_data.append(int(time.time()))

                except Exception as e:
                    a = 1
                    logger.error(
                        "Error in getting ip address through lumtest ({})".format(e))

        print("skk")
        async with session.get(url='http://{}.{}'.format(exp_id, QUERY_URL), proxy=proxy_url) as response:
            try:
                print("ghere")
                result_data = await response.read()
                which_host = check_host(result_data)
                resolution_data.append(which_host)
                resolution_data.append(int(time.time()))

            except Exception as e:
                a = 1
                logger.error(
                    "Error in getting ip address through lumtest ({})".format(e))

            global store_tuples
            store_tuples.append(resolution_data)

    except Exception as e:
        pass


async def process_ocsp_urls_async(chosen_hop_list, exp_id, phase):
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for i in range(5):
            for hop in chosen_hop_list:
                try:
                    import random
                    task = asyncio.ensure_future(
                        query_through_luminati(hop=hop, session=session, exp_id=exp_id, phase=phase))
                    tasks.append(task)
                except Exception as e:
                    logger.error("Error in Processing hop {}: {}".format(hop, e))
        execution_results = await asyncio.gather(*tasks)


def luminati_asn_ttl_crawler(exp_id, file_date):
    starting_time = time.time()
    msg = "Luminati ttl exp started at {}".format(starting_time)
    send_telegram_msg(msg=msg)

    chosen_hop_list = choose_hops_for_ttl_exp(file_date)
    msg = "Total asns {}".format(len(chosen_hop_list))
    send_telegram_msg(msg=msg)
    asn_chunks = chunks(chosen_hop_list, 500)

    for chunk in asn_chunks:
        asyncio.run(process_ocsp_urls_async(chosen_hop_list=chunk, exp_id=exp_id, phase=1))

    msg = "Luminati ttl exp phase 1 done, time taken: {}".format(time.time() - starting_time)
    send_telegram_msg(msg=msg)
    from time import sleep

    sleep(60*60 + 120)

    for chunk in asn_chunks:
        asyncio.run(process_ocsp_urls_async(chosen_hop_list=chunk, exp_id=exp_id, phase=2))
    msg = "Luminati ttl exp phase 2 done"
    send_telegram_msg(msg=msg)

    elapsed_time = time.time() - starting_time
    print("Elapsed time {}".format(elapsed_time))

    msg = "Luminati ttl exp done, elapsed time {}".format(elapsed_time)
    send_telegram_msg(msg=msg)

    with open("{}-ttl_exp.json".format(exp_id), "w") as ouf:
        json.dump(store_tuples, fp=ouf)


def send_telegram_msg(msg):
    import telegram_send
    telegram_send.send(messages=[msg])
