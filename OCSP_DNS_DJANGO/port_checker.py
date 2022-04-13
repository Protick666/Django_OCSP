from time import sleep
import socket, ipaddress, threading
port = 53
from dns import resolver

max_threads = 4000
port_reachable = {}
dns_answer = {}
dns_error = {}

err = 0

mx = 0


def check_port(ip, port, ind):
    global port_reachable
    global mx
    global dns_error
    global dns_answer
    global dns_answer
    global dns_error
    try:

        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        socket.setdefaulttimeout(3) # seconds (float)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # print ("Port is open")
            port_reachable[ip] = "OPEN"
        else:
            # print ("Port is closed/filtered")
            port_reachable[ip] = "CLOSED"
        sock.close()
        mx = max(mx, ind)
        print("Done with {}".format(ind))
    except:
        port_reachable[ip] = "UNKNOWN"
        pass

    try:
        res = resolver.Resolver()
        res.nameservers = [ip]
        answers = res.resolve('google.com', lifetime=4)
        for rdata in answers:
            dns_answer[ip] = rdata.address
            return

    except Exception as e:
        dns_error[ip] = ((str(e.__class__.__name__), str(e)))
        pass



import json
from OCSP_DNS_DJANGO.local import LOCAL

if LOCAL:
    f = open("../public_resolver_all.json")
else:
    f = open("/home/protick/ocsp_dns_django/ttl_result_v2/public_resolver_all.json")
ip_list = json.load(f)
ip_list = list(set(ip_list))
# ip_list = ip_list[:2000]
ip_size = len(ip_list)

id = 0
for ip in ip_list:
    id += 1
    threading.Thread(target=check_port, args=[str(ip), port, id]).start()
    #sleep(0.1)
    # limit the number of threads.
    while threading.active_count() > max_threads :
        sleep(1)


# port_reachable = {}
# dns_answer = {}
# dns_error = {}

while len(dns_error.keys()) + len(dns_answer.keys()) < ip_size - 100:
    sleep(10)

sleep(30)

p = {
    "port_reachable": port_reachable,
    "dns_answer": dns_answer,
    "dns_error": dns_error,
    "ip_list": ip_list
}

with open("public_verdict_2.json", "w") as ouf:
    json.dump(p, fp=ouf)