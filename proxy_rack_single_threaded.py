#!/usr/bin/python2.7
# We run this program on CentOS6 with Python 2.7.6. Other combinations have not been tested.

# Basic
import os, time
import json, random
from random import Random
import signal, functools
# DNS-related
from dnsmsg import DNSquery, DNSresponse
from name import *
# Network
import requests
import socks
import ssl
import struct


#### Timeout handling functions ####
class TimeoutError(Exception): pass

def timeout(seconds, error_message="Timeout Error, Something wrong with ProxyRack."):
    def decorated(func):
        result = ""
        def _handle_timeout(signum, frame):
            global result
            result = error_message
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            global result
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)

            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
                return result
            return result

        return functools.wraps(func)(wrapper)

    return decorated

class ErrorMessage(Exception):
    def __init__(self,ErrorInfo):
        Exception.__init__(self)
        self.errorinfo=ErrorInfo
    def __str__(self):
        return self.errorinfo
#### Timeout handling functions ####


###################### GLOBAL VARIABLES ######################
# Maximum number of retry time.
retry = 5
# The URL to get the nodes's IP.
IP_URL = "http://ip-api.com/json"

# ProxyRack settings.
PROXY_UNAME = "user"
PROXY_PWD = "password"
PORT_FIRST = 1500
PORT_LAST = 1750
PROXY_DOMAIN = ".megaproxy.rotating.proxyrack.net"

# The test domain name.
TEST_DOMAIN = "test-doe"

# Public resolver addresses.
CF_DNS = "1.1.1.1"
CF_DOH_TEMPLATE = "https://cloudflare-dns.com/dns-query"
GOOGLE_DNS = "8.8.8.8"
GOOGLE_DOH_TEMPLATE = "https://dns.google.com/resolve"  # After Sept 24, this domain will be redirected to its successor, https://dns.google/.
QUAD9_DNS = "9.9.9.9"
QUAD9_DOH_TEMPLATE = "https://dns.quad9.net/dns-query"
# The self-built resolver.
SELF_RESOLVER_IP = "x.x.x.x"
SELF_RESOLVER_DOH_TEMPLATE = "https://self-built/dns-query"

# Keep this flag as False for reachability tests.
# To measure performance with connection reuse, modify the python libraries and turn on the flag.
lib_change = False
###################### GLOBAL VARIABLES ######################


# generate a random string for the UUID of each node.
def random_str(random_length=16):
    str = ''
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    length = len(chars) - 1
    random = Random()
    for count in range(random_length):
        str += chars[random.randint(0, length)]
    return str


#### get IP address of this proxy node over HTTP
@timeout(15)
def get_ip_http(proxy_addr):
    import requests

    username = PROXY_UNAME
    password = PROXY_PWD
    proxy = {"http": "http://{}:{}@{}".format(username, password, proxy_addr)}

    ip_get_flag = False
    json_content = None

    for count in range(0, retry):
        try:
            if lib_change:
                r = requests.get(IP_URL, proxies=proxy)[0]
            else:
                r = requests.get(IP_URL, proxies=proxy)
            ip_get_flag = True
            json_content = json.loads(r.text)
            break
        except Exception as e:
            json_content = str(e)

    return ip_get_flag, json_content


#### Perform a DNS-over-TCP query
@timeout(30)
def dns_query_tcp(UUID, resolver):
    import dns.query

    tcp_response_flag = False
    tcp_response_content = None
    tcp_rtt = None
    tcp_rtt_new = None

    for count in range(0, retry):
        domain = UUID + "-" + resolver.replace(".", "-") + "-TCP." + TEST_DOMAIN
        qname = dns.name.from_text(domain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
        begin = 0
        try:
            # send this query and get response
            begin = time.time()
            tcp_response_content = dns.query.tcp(q, resolver, timeout=20)
            end = time.time()
            tcp_rtt = end - begin
            tcp_rtt_new = tcp_response_content.time     # (to calc this, you need to modify /usr/lib/python2.7/site-packages/dns/query.py, function tcp())
            tcp_response_flag = True
            break
        except Exception as e:
            tcp_response_content = str(e)
            end = time.time()
            tcp_rtt = end - begin

    return tcp_response_flag, tcp_response_content, tcp_rtt, tcp_rtt_new


#### Perform a DNS-over-HTTPS query
@timeout(30)
def dns_query_https(UUID, resolver, proxy_addr):
    dns_https_response_flag = False
    dns_https_response_content = None
    dns_https_rtt = None
    dns_https_rtt_new = None

    username = PROXY_UNAME
    password = PROXY_PWD
    proxy = {"http": "http://{}:{}@{}".format(username, password, proxy_addr)}

    for count in range(0, retry):
        # customize for the different DoH template of each resolver.
        if resolver == GOOGLE_DNS:
            domain = UUID + "-" + resolver.replace(".", "-") + "-HTTPS." + TEST_DOMAIN
            res_dom = GOOGLE_DOH_TEMPLATE
            begin = 0
            try:
                begin = time.time()
                if lib_change:
                    r, dns_https_rtt_new = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy,
                                                        timeout=30)
                else:
                    r = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy, timeout=30)
                end = time.time()
                dns_https_rtt = end - begin
                dns_https_response_content = str(r.text)
                dns_https_response_flag = True
                break
            except Exception as e:
                dns_https_response_content = str(e)
                end = time.time()
                dns_https_rtt = end - begin

        elif resolver == CF_DNS:
            domain = UUID + "-" + resolver.replace(".", "-") + "-HTTPS." + TEST_DOMAIN
            res_dom = CF_DOH_TEMPLATE
            # Use JSON format for simplicity.
            header = {"accept": "application/dns-json"}
            begin = 0
            try:
                begin = time.time()
                if lib_change:
                    r, dns_https_rtt_new = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy,
                                                        headers=header, timeout=30)
                else:
                    r = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy, headers=header, timeout=30)
                end = time.time()
                dns_https_rtt = end - begin
                dns_https_response_content = str(r.text)
                dns_https_response_flag = True
                break
            except Exception as e:
                dns_https_response_content = str(e)
                end = time.time()
                dns_https_rtt = end - begin

        elif resolver == QUAD9_DNS:
            domain = UUID + "-" + resolver.replace(".", "-") + "-HTTPS." + TEST_DOMAIN
            res_dom = QUAD9_DOH_TEMPLATE
            begin = 0
            try:
                begin = time.time()
                if lib_change:
                    r, dns_https_rtt_new = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy,
                                                        timeout=30)
                else:
                    r = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy, timeout=30)
                end = time.time()
                dns_https_rtt = end - begin
                dns_https_response_content = str(r.text)
                dns_https_response_flag = True
                break
            except Exception as e:
                dns_https_response_content = str(e)
                end = time.time()
                dns_https_rtt = end - begin

        elif resolver == SELF_RESOLVER_IP:
            domain = UUID + "-" + resolver.replace(".", "-") + "-HTTPS." + TEST_DOMAIN
            res_dom = SELF_RESOLVER_DOH_TEMPLATE
            begin = 0
            try:
                begin = time.time()
                if lib_change:
                    r, dns_https_rtt_new = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy,
                                                        timeout=30)
                else:
                    r = requests.get(res_dom + "?name=" + domain + "&type=A", proxies=proxy, timeout=30)
                end = time.time()
                dns_https_rtt = end - begin
                dns_https_response_content = str(r.text)
                dns_https_response_flag = True
                break
            except Exception as e:
                dns_https_response_content = str(e)
                end = time.time()
                dns_https_rtt = end - begin

    return dns_https_response_flag, dns_https_response_content, dns_https_rtt, dns_https_rtt_new



#### A set of TLS functions, used for DNS-over-TLS queries. ####
def sendSocket(s, message):
    """Send message on a connected socket"""
    try:
        octetsSent = 0
        while (octetsSent < len(message)):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                raise ErrorMessage("send() returned 0 bytes")
            octetsSent += sentn
    except Exception as e:
        print("DEBUG: Exception: %s" % e)
        return False
    else:
        return True

def recvSocket(s, numOctets):
    """Read and return numOctets of data from a connected socket"""
    response = b""
    octetsRead = 0
    while (octetsRead < numOctets):
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return b""
        octetsRead += chunklen
        response += chunk
    return response

def get_ssl_context(tls_auth, hostname):
    """Return SSL context object"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    except:
        if hostname:
            print("Warning: Hostname checking unavailable in ssl module.")
        return None
    else:
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1

        ## Windows may need: ctx.load_default_certs() - untested
        ctx.set_default_verify_paths()

        if tls_auth:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE

        if hostname:
            try:
                ctx.check_hostname = True
            except AttributeError:
                print("Warning: Hostname checking unavailable in ssl module.")

        return ctx

def get_ssl_connection(ctx, s, hostname):
    """Return SSL/TLS connection object"""
    if ctx:
        return ctx.wrap_socket(s, server_hostname=hostname)
    else:
        return ssl.wrap_socket(s)

def send_request_tls(pkt, host, port, family=socket.AF_INET, hostname=None):
    pkt = struct.pack("!H", len(pkt)) + pkt       # prepend 2-byte length
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(30)
    response = ""
    rtt_new = 0

    ctx = get_ssl_context(False, hostname)

    try:
        s.connect((host, port))
        conn = get_ssl_connection(ctx, s, hostname)
    except socket.error as e:
        response = "socket error: " + str(e)
    except ssl.SSLError as e:
        response = "TLS error: " + str(e)
    except Exception as e:
        response = "Other error: " + str(e)
    else:
        rtt_new = time.time()
        if not sendSocket(conn, pkt):
            response = "Error: send() on socket Failed."
        else:
            lbytes = recvSocket(conn, 2)
            if (len(lbytes) != 2):
                response = "Error: recv() on socket Failed." + str(len(lbytes))
            else:
                resp_len, = struct.unpack('!H', lbytes)
                response = recvSocket(conn, resp_len)
    finally:
        if "conn" in vars().keys():
            conn.close()
    rtt_new = time.time() - rtt_new

    return response, rtt_new
#### A set of TLS functions, used for DoT queries. ####

#### Perform a DNS over TLS query.
@timeout(30)
def dns_query_tls(UUID, resolver):
    dns_tls_flag = False
    dns_tls_response = None
    dns_tls_rtt = None
    dns_tls_rtt_new = None

    # make a wire-format DNS query first.
    query = DNSquery(UUID + "-" + resolver.replace(".", "-") + "-TLS." + TEST_DOMAIN, 1, 1)

    for count in range(0, retry):
        begin = 0
        try:
            begin = time.time()
            responsepkt, dns_tls_rtt_new = send_request_tls(query.get_message(), resolver, 853)
            end = time.time()
            dns_tls_rtt = end - begin
            try:
                # this is a fix for the ErrorMessage in dnsmsg.py.
                dns_tls_response = DNSresponse(socket.AF_INET, query, responsepkt)
                dns_tls_flag = True
                break
            except:
                dns_tls_response = str(responsepkt)
        except Exception as e:
            dns_tls_response = str(e)
            end = time.time()
            dns_tls_rtt = end - begin

    return dns_tls_flag, dns_tls_response, dns_tls_rtt, dns_tls_rtt_new


######## Webpage & Port probe ########
# Fetch the HTTP webpage of the CloudFlare resolver.
@timeout(20)
def get_quad_one_http_webpage():
    quad_one_http_url = "http://1.1.1.1"

    quad_one_http_web_flag = False
    quad_one_http_web_detail = None

    for count in range(0, retry):
        try:
            if lib_change:
                quad_one_http_web_detail = requests.get(quad_one_http_url)[0].content
            else:
                quad_one_http_web_detail = requests.get(quad_one_http_url).content
            quad_one_http_web_flag = True
            break
        except Exception as e:
            quad_one_http_web_detail = str(e)

    return quad_one_http_web_flag, quad_one_http_web_detail

# Fetch the HTTPS webpage of the CloudFlare resolver.
@timeout(20)
def get_quad_one_https_webpage():
    quad_one_https_url = "https://1.1.1.1"

    quad_one_https_web_flag = False
    quad_one_https_web_detail = None
    for count in range(0, retry):
        try:
            if lib_change:
                quad_one_https_web_detail = requests.get(quad_one_https_url)[0].content
            else:
                quad_one_https_web_detail = requests.get(quad_one_https_url).content
            quad_one_https_web_flag = True
            break
        except Exception as e:
            quad_one_https_web_detail = str(e)

    return quad_one_https_web_flag, quad_one_https_web_detail

# probe the common ports on address 1.1.1.1.
@timeout(300)
def scanning_port(famous_port):
    response_port = famous_port
    for port in famous_port:

        for count in range(0, retry):
            sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sk.settimeout(10)
            try:
                sk.connect(('1.1.1.1', int(port)))
                response_port[port] = 'open'
                break
            except Exception as e:
                response_port[port] = str(e)
            sk.close()
    return response_port

# perform the entire webpage & port probe process.
@timeout(500)
def fingerprinting_quad1(proxy_addr):
    # SSH (TCP/22), Telnet (TCP/23), DNS(UDP/53), DHCP(UDP/67), HTTP(TCP/80),
    # NTP (UDP/123), SMB (TCP/139), SNMPv2 (UDP/161), BGP (TCP/179), HTTPS (TCP/443)
    # TCP protocol
    famous_port = {'22': 'closed', '23': 'closed', '53': 'closed', '67': 'closed',
                   '80': 'closed', '123': 'closed', '139': 'closed', '161': 'closed',
                   '179': 'closed', '443': 'closed'}

    response_port_result = scanning_port(famous_port)
    webpage_http = get_quad_one_http_webpage()
    webpage_https = get_quad_one_https_webpage()

    return response_port_result, webpage_http, webpage_https

# get the SSL certificate on one server.
@timeout(60)
def shake_hands_certificate(resolver, port, proxy_addr):
    certificate_flag = False
    cert = None

    username = PROXY_UNAME
    password = PROXY_PWD
    proxy = {"http": "http://{}:{}@{}".format(username, password, proxy_addr)}
    ip = resolver

    for count in range(0, retry):
        try:
            sk = socket.socket()
            sk.settimeout(20)

            sk.connect((ip, port))
            # the ca_certs parameter might be OS-specific.
            con = ssl.wrap_socket(sk, cert_reqs=ssl.CERT_REQUIRED, ca_certs="/etc/ssl/certs/ca-bundle.crt")
            con.settimeout(20)
            cert = con.getpeercert()
            certificate_flag = True
            break
        except Exception as e:
            cert = str(e)

    return certificate_flag, str(cert)





############################## Main function #############################
def main():
    start_time = str(time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()))

    # The final report JSON
    report = {}
    report["IP"] = {}
    report["TCP"] = {}
    report["TLS"] = {}
    report["HTTPS"] = {}
    report["Certificate"] = {}
    report["Quad_one"] = {}

    # UUID information
    UUID = random_str(13)

    # first set the proxy
    username = PROXY_UNAME
    password = PROXY_PWD

    # The port range given by ProxyRack. pick one node from the list.
    port_int = random.randint(PORT_FIRST, PORT_LAST)
    # Will the node be up for the next 15 minutes? if not, change one.
    try:
        API_IP = "y.y.y.y"
        expire = os.popen("curl -m 30 -x " + API_IP + ":" + str(port_int)
                          + " -U " + username + ":" + password + " refresh_timestamp").read()
        now = time.time()
        expire = int(expire) / 1000
        if expire - now < 15 * 60:
            return
    except:
        return
    # set the proxy for requests.
    socks.set_default_proxy(socks.SOCKS5, str(port_int) + PROXY_DOMAIN, port_int,
                             username=username, password=password)
    socket.socket = socks.socksocket

    ''' TEST BEGINS '''
    BEGIN_TIME = time.time()
    # Get the IP address of the proxy node (by HTTP)
    proxy_addr = str(port_int) + PROXY_DOMAIN + str(port_int)
    ip_get_flag, http_response = get_ip_http(proxy_addr)
    report["IP"]["status"] = ip_get_flag
    report["IP"]["content"] = http_response
    if not ip_get_flag:
        # this node is unavailable. can't get its IP address.
        return
    
    # The Set of tested resolvers.
    Public_DNS = [CF_DNS, GOOGLE_DNS, QUAD9_DNS, SELF_RESOLVER_IP]

    # DNS-over-TCP queries #####
    for eachresolver in Public_DNS:
        report["TCP"][eachresolver] = {}
        tcp_response_flag, tcp_response_content, tcp_rtt, tcp_rtt_new = dns_query_tcp(UUID, eachresolver)
        report["TCP"][eachresolver]["flag"] = tcp_response_flag
        report["TCP"][eachresolver]["content"] = str(tcp_response_content)
        # the latency with connection establishment
        report["TCP"][eachresolver]["rtt"] = tcp_rtt
        # the latency without connection establishment
        report["TCP"][eachresolver]["rtt_new"] = tcp_rtt_new

    # DNS-over-HTTPS queries #####
    for eachresolver in Public_DNS:
        report["HTTPS"][eachresolver] = {}
        dns_https_response_flag, dns_https_response_content, dns_https_rtt, dns_https_rtt_new = dns_query_https(UUID, eachresolver, proxy_addr)
        report["HTTPS"][eachresolver]["flag"] = dns_https_response_flag
        report["HTTPS"][eachresolver]["content"] = str(dns_https_response_content)
        report["HTTPS"][eachresolver]["rtt"] = dns_https_rtt
        report["HTTPS"][eachresolver]["rtt_new"] = dns_https_rtt_new

    # DNS-over-TLS queries #####
    for eachresolver in Public_DNS:
        report["TLS"][eachresolver] = {}
        dns_tls_flag, dns_tls_response, dns_tls_rtt, dns_tls_rtt_new = dns_query_tls(UUID, eachresolver)
        if dns_tls_flag:
            parse_packet = str(dns_tls_response.parse())
            report["TLS"][eachresolver]["flag"] = dns_tls_flag
            report["TLS"][eachresolver]["content"] = parse_packet
            report["TLS"][eachresolver]["rtt"] = dns_tls_rtt
            report["TLS"][eachresolver]["rtt_new"] = dns_tls_rtt_new
        else:
            report["TLS"][eachresolver]["flag"] = dns_tls_flag
            report["TLS"][eachresolver]["content"] = dns_tls_response
            report["TLS"][eachresolver]["rtt"] = None

    # Collecting Certificate from DNS server #####
    for eachresolver in Public_DNS:
        report["Certificate"][eachresolver] = {}
        report["Certificate"][eachresolver]["443"] = {}
        certificate_flag, certificate_content = shake_hands_certificate(eachresolver, 443, proxy_addr)
        report["Certificate"][eachresolver]["443"]["flag"] = certificate_flag
        report["Certificate"][eachresolver]["443"]["content"] = certificate_content

        report["Certificate"][eachresolver]["853"] = {}
        certificate_flag, certificate_content = shake_hands_certificate(eachresolver, 853, proxy_addr)
        report["Certificate"][eachresolver]["853"]["flag"] = certificate_flag
        report["Certificate"][eachresolver]["853"]["content"] = certificate_content

    # fingerprint information of 1.1.1.1.
    response_port_result, webpage_http, webpage_https = fingerprinting_quad1(proxy_addr)
    report["Quad_one"]["port"] = response_port_result
    report["Quad_one"]["http"] = str(webpage_http)
    report["Quad_one"]["https"] = str(webpage_https)

    # dump the result to one file.
    f_w = open("data/" + start_time + "." + UUID + ".txt", 'a')
    f_w.write(json.dumps(report))
    f_w.close()

    ''' PROCESS ENDS '''
    END_TIME = time.time()

# Program starts
while True:
    main()
