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


def main():
    if len(sys.argv) == 2:
        name = sys.argv[1]
        if name != '':
            print("Found using 'Cookie Knowledge' :]\n")
            ips = lookup(name)
            if ips:
                print(f"'{name}' IPs: {', '.join(ips)}")
            else:
                print(f"No IPs found for '{name}'")
        else:
            print("Usage: python nslookup.py <domain>")
    else:
        print("Usage: python nslookup.py <domain>")


if __name__ == '__main__':
    main()
