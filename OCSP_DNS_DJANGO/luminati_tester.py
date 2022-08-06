import asyncio
import logging
import time

import aiohttp
import django
import uuid
from OCSP_DNS_DJANGO.local import LOCAL, LOCAL_REDIS_HOST, REMOTE_REDIS_HOST
from OCSP_DNS_DJANGO.loominati_helper_tools import get_total_cert_per_ocsp_url, \
    choose_hops_for_ttl_exp_v2, choose_candidate_asns
from OCSP_DNS_DJANGO.tools import chunks
import requests

django.setup()

logger = logging.getLogger(__name__)
# logger.info("Starting ocsp job now !")
QUERY_URL = 'securekey.app'

HOST_DICT = {
    "first": 1,
    "second": 2
}

# logs: /var/log/bind, /var/log/apache2
# TODO how to serve NXDOMAIN
# TODO check interim logs


def interim_checks(exp_id, iter, event, depth=0):
    if depth == 5:
        return False
    uid = uuid.uuid4()
    URL = "http://{}.{}.{}.{}.{}".format(uid, exp_id, iter, event, QUERY_URL)
    r = requests.get(url=URL)
    if r.status_code != 200:
        return interim_checks(exp_id, iter, event, depth + 1)
    return True


def change_bind_config(file_version, ttl, depth=0):
    if depth == 5:
        return False

    URL = "http://52.44.221.99:8000/update-bind"
    PARAMS = {'file_version': file_version, 'ttl': str(ttl)}
    r = requests.get(url=URL, params=PARAMS)
    data = r.json()
    if r.status_code != 200:
        return change_bind_config(file_version, ttl, depth + 1)
    return True

# 52.44.221.99 -> phase1
# 3.220.52.113 -> phase 2

dict_of_phases = {}
meta_data = {}

def check_host(result_data):
    str = result_data.decode("utf-8")
    if 'phase1' in str:
        return 1
    elif 'phase2' in str:
        return 2
    raise Exception


async def query_through_luminati(hop, session, exp_id, phase):
    try:
        global dict_of_phases

        import random, string, time
        letters = string.ascii_lowercase
        #uid = str(uuid.uuid4())
        session_key = ''.join(random.choice(letters) for i in range(8)) + str(int(time.time()))


        req_id = None
        asn, hop_identifier = hop
        proxy_url = 'http://lum-customer-c_9c799542-zone-protick-dns-remote-asn-{}-session-{}:cbp4uaamzwpy@zproxy.lum-superproxy.io:22225'.format(
            asn, session_key)


        async with session.get(url='http://{}.{}.{}'.format(asn, exp_id, QUERY_URL), proxy=proxy_url) as response:
            try:
                result_data = await response.read()
                headers = response.headers
                which_host = check_host(result_data)
                print(which_host)
            except Exception as e:
                #logger.error("Error ({})".format(str(e)))
                pass

    except Exception as e:
        #logger.error("Error ({})".format(str(e)))
        pass



async def process_ocsp_urls_async(chosen_hop_list, exp_id, phase):
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = []
        for hop in chosen_hop_list:
            try:
                import random
                task = asyncio.ensure_future(
                    query_through_luminati(hop=hop, session=session, exp_id=exp_id, phase=phase))
                tasks.append(task)
            except Exception as e:
                #logger.error("Error in Processing hop {}: {}".format(hop, str(e)))
                pass
        execution_results = await asyncio.gather(*tasks)


def carry_out_exp(exp_id, hops, iter, offset, ttl, cool_down, chunk_size):
    asn_chunks = chunks(hops[offset:], chunk_size)
    return_offset = len(hops)

    starting_time = time.time()
    msg = "Starting iteration {} at {}".format(iter, starting_time)

    chunk_count = 1
    processed_hops = []

    for chunk in asn_chunks:
        asyncio.run(process_ocsp_urls_async(chosen_hop_list=chunk, exp_id=exp_id, phase=1))
        time_now = time.time()
        processed_hops = processed_hops + chunk
        chunk_count += 1

    # msg = "Luminati ttl exp phase 1 done, time taken: {}".format(time.time() - starting_time)
    # send_telegram_msg(msg=msg)



def luminati_asn_ttl_crawler_req(exp_id, TTL_IN_SEC, TOTAL_REQUESTS, chunk_size):

    COOL_DOWN_PERIOD = TTL_IN_SEC
    # chunk_size = 2000
    meta_data['ttl'] = TTL_IN_SEC
    meta_data['target_req'] = TOTAL_REQUESTS
    meta_data['chunk_size'] = chunk_size

    starting_time = time.time()
    msg = "Luminati ttl exp {} started at {}".format(exp_id, starting_time)
    send_telegram_msg(msg=msg)

    chosen_hop_list = choose_candidate_asns()

    iter = 1
    offset = 0

    while offset < len(chosen_hop_list):
        offset = carry_out_exp(exp_id=exp_id,
                               hops = chosen_hop_list,
                               iter=iter, offset=offset,
                               ttl=TTL_IN_SEC,
                               cool_down=COOL_DOWN_PERIOD,
                               chunk_size=chunk_size)
        # TODO change this after an estimation
        target_req_number = len(chosen_hop_list)
        fulfilled_count = offset

        msg = "{} targets done out of {}".format(fulfilled_count, target_req_number)
        meta_data['target_req_number'] = target_req_number
        meta_data['fulfilled_count'] = fulfilled_count
        send_telegram_msg(msg=msg)
        break
        iter += 1

    elapsed_time = time.time() - starting_time
    print("Elapsed time {}".format(elapsed_time))
    msg = "Luminati ttl exp fully done, elapsed time {}".format(elapsed_time/60)
    meta_data['total_time'] = elapsed_time/60
    send_telegram_msg(msg=msg)

    store_dict = {}
    store_dict['exp_id'] = exp_id
    store_dict['meta_data'] = meta_data
    store_dict['dict_of_phases'] = dict_of_phases
    import json
    with open("ttldict/{}-ttl_exp.json".format(exp_id), "w") as ouf:
        json.dump(store_dict, fp=ouf)


def zeus_mami111():
    for i in range(4, 7):
        luminati_asn_ttl_crawler_req(exp_id="live{}".format(i), TTL_IN_SEC=3600, TOTAL_REQUESTS=300000, chunk_size=2000)
        time.sleep(60*10)


def send_telegram_msg(msg):
    return
    import telegram_send
    telegram_send.send(messages=[msg])
