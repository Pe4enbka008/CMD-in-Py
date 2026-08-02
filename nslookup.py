from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
import sys


def lookup(name):
    """The function is a recreation of nslookup, but using Python :]
    :param name: domain's name
    :type name: str
    :return: List of resolved IP addresses (could be empty)
    :rtype: list[str]
    """
    dns_query = (
        IP(dst="8.8.8.8") /
        UDP(sport=RandShort(), dport=53) /
        DNS(rd=1, qd=DNSQR(qname=name))
    )

    response = sr1(dns_query, verbose=0, timeout=2)
    if response and response.haslayer(DNS) and response[DNS].ancount > 0:
        result = []
        for i in range(response[DNS].ancount):
            answer = response[DNS].an[i]
            if answer.type == 1:  # A record (IPv4)
                result.append(answer.rdata)
        return result
    return []


def do_lookup(domain):
    """The function calls lookup function
    :param domain: domain name
    :type domain: str
    :return: nothing
    :rtype: None"""
    # making the link usable even without writing .com
    if '.' not in domain and not domain.replace('.', '').isdigit():
        domain += '.com'
    ips = lookup(domain)
    if ips:
        print(f"'{domain}' IPs: {', '.join(ips)}")
    else:
        print(f"No IPs found for '{domain}'")


def main():
    if len(sys.argv) == 2:
        name = sys.argv[1]
    else:
        print("Usage: python nslookup.py <domain>")
        print("Found using 'Cookie Knowledge' :]\n")
        name = input("But I'll still allow it :]\nDomain name plz: ")

    if len(sys.argv) != 2:
        while name != '':
            do_lookup(name)
            name = input("But I'll still allow it :]\nDomain name plz: ")
    elif name != '' and len(sys.argv) == 2:
        print("Found using 'Cookie Knowledge' :]\n")
        do_lookup(name)
    else:
        print("Usage: python nslookup.py <domain>")


if __name__ == '__main__':
    main()
