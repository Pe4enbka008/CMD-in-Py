from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
import datetime as dt
import sys
from nslookup import lookup


def ping(ip):
    """The function is a recreation of ping, but using Python :]
    :param ip: domain's IP/name
    :type ip: str
    :return: nothing
    :rtype: None"""
    original = ip
    if ip[0] not in '1234567890':
        ip = lookup(ip)[0]  # only first ip
    if not ip:
        print("Invalid domain or IP.")
        return []

    print(f"Pinging {original} [{ip}] with some data:")

    responses = []
    times = []
    received = 0
    for _ in range(4):
        packet = IP(dst=ip) / ICMP()
        start = dt.datetime.now()
        reply = sr1(packet, timeout=2, verbose=0)
        end = dt.datetime.now()

        if reply:
            elapsed = (end - start).total_seconds() * 1000
            responses.append(f"Reply from {reply[IP].src}: it took {int(elapsed)}ms, TTL left: {reply[IP].ttl}")
            times.append(elapsed)
            received += 1
        else:
            responses.append("Request timed out :[")
            times.append(0)

    print('\n'.join(responses))

    sent = 4
    lost = sent - received
    loss_percent = int((lost / sent) * 100)

    print(f"\nPing statistics for {ip}:")
    print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percent}% loss),")

    successful_times = [t for t in times if t > 0]
    if successful_times:
        print("Stats for the trips:")
        print(f"    Minimum = {int(min(successful_times))}ms, Maximum = {int(max(successful_times))}ms, Average = {int(sum(successful_times)/len(successful_times))}ms")
    else:
        print("No successful replies :[  No timing data.")


def main():
    if len(sys.argv) == 2:
        ip = sys.argv[1]
        if ip != '':
            print("Found using 'Cookie Knowledge' :]\n")
            ping(ip)
        else:
            print("Usage: python ping_pong.py <domain>")
    else:
        print("Usage: python ping_pong.py <domain>")


if __name__ == '__main__':
    main()
