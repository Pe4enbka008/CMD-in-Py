from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
import datetime as dt
import sys
from nslookup import lookup


def trace(ip):
    """The function is a recreation of traceroute, but using Python :]
    :param ip: domain's IP/name
    :type ip: str
    :return: nothing
    :rtype: None"""
    name = ip
    if ip[0] not in '1234567890':
        ip = lookup(ip)[0]  # only first ip
    if not ip:
        print("Invalid domain or IP.")
        return

    print(f"\nTracing route to {name} [{ip}]")

    ttl = 1
    while ttl <= 30:
        times = []
        src_ip = None
        for _ in range(3):
            packet = IP(dst=ip, ttl=ttl) / ICMP()
            start = dt.datetime.now()
            reply = sr1(packet, timeout=2, verbose=0)
            end = dt.datetime.now()

            if reply:
                time_ms = (end - start).total_seconds() * 1000
                times.append(f"{int(time_ms)}ms")
                src_ip = reply.src
            else:
                times.append("??")

        line = f"{ttl:>2}   " + '   '.join(f"{t:<4}" for t in times)  # formatting!
        if src_ip:
            line += f"  {src_ip}"
        print(line + '  :>')

        if src_ip == ip:
            break

        ttl += 1

    print("\nTrace complete :>")


def main():
    if len(sys.argv) == 2:
        ip = sys.argv[1]
        if ip != '':
            print("Found using 'Cookie Knowledge' :]\n")
            trace(ip)
        else:
            print("Usage: python tracert.py <domain>")
    else:
        print("Usage: python tracert.py <domain>")


if __name__ == '__main__':
    main()
