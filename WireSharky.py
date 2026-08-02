# from scapy.all import sniff
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw
import time


def printf(val=''):
    """Fun function for printing on the same line
    inspired by Console.Write() from C# and printf from C
    :param val: value to print
    :type val: str
    :return: nothing
    :rtype: None"""
    print(val, end="")


# Communication with user
def menu():
    """Prints menu for the user
    :return: nothing
    :rtype: None"""
    print("\nPlease select sniffing state:")
    print('To stop sniffer press Ctrl+C :] ( Works in cmd, no Pycharm :[ )')
    for key, func in functions.items():
        print(f"{key}. {func[0]}") if key != '0' else printf()
    printf("Or select 0 to Exit: ")


def receive_choice():
    """Receives correct user choice
    :return: user choice
    :rtype: str"""
    menu()
    choice = input()
    while choice not in list(functions.keys()):
        print("Invalid choice, try again!\n")
        menu()
        choice = input()
    return choice


def print_dns_results(packet):
    """Help function for scapy.sniff() to print while sniffing DNS
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: nothing
    :rtype: None"""
    if DNS in packet and packet[DNS].qr == 1 and packet[DNS].an:
        try:
            domain = '<' + packet[DNS].qd.qname.decode(errors='ignore').rstrip('.') + '>'
            print(f"DNS-ing: {domain} -> '{packet[DNS].an.rdata}'")

        except Exception as e:
            print(f"[!] Error: {e}")


def print_weather_results(packet):
    """Help function for scapy.sniff() to print while sniffing WeatherClient
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: nothing
    :rtype: None"""
    if Raw in packet:
        data = '<' + packet[Raw].load.decode(errors='ignore') + '>'  # skip any invalid bytes
        print("Server answer:", data)


def print_http_results(packet):
    """Help function for scapy.sniff() to print while sniffing HTTP packets
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: nothing
    :rtype: None"""
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors='ignore')  # skip any invalid bytes
        printf("Got a HTTP answer:\n" + data)


def print_smtp_results(packet):
    """Help function for scapy.sniff() to print SMTP sender and receiver emails
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: nothing
    :rtype: None"""
    if packet.haslayer(Raw):
        data = packet[Raw].load.decode(errors='ignore')  # decode raw payload
        sender_code = 'MAIL FROM:'
        receiver_code = 'RCPT TO:'
        sender = None
        receiver = None

        for line in data.split('\r\n'):
            if line.upper().startswith(sender_code):
                sender = line[len(sender_code):].strip()  # everything after 'MAIL FROM:'
            elif line.upper().startswith(receiver_code):
                receiver = line[len(receiver_code):].strip()  # everything after 'RCPT TO:'

        if sender or receiver:
            printf("You got mail: ")
            if sender:
                printf(f"{sender} -> ")
            if receiver:
                printf(f"{receiver}")
            print()


# Communication with sniff
def sniff_dns(packet):
    """Help function for scapy.sniff() to sort while sniffing DNS
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: If the packet:
        contains UDP and port 53 (DNS port)
        contains DNS, DNS answer and it contains IP
    :rtype: bool"""
    return packet.haslayer(UDP) and packet[UDP].sport == 53 and \
           DNS in packet and packet[DNS].qr == 1 and packet[DNS].an \
           and packet[DNS].an.type == 1


def sniff_weather(packet):
    """Help function for scapy.sniff() to sort while sniffing WeatherClient
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: If the packet:
        contains Raw and it's code 200
        from IP 34.218.16.79
    :rtype: bool"""
    return packet.haslayer(IP) and packet[IP].src == "34.218.16.79" and \
           packet.haslayer(Raw) and b'200' in packet[Raw].load


def sniff_http(packet):
    """Help function for scapy.sniff() to sort while sniffing HTTP packets
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: If the packet:
        contains TCP and port 80 (HTTP port)
        contains Raw and it's GET request
    :rtype: bool"""
    return packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].dport == 80) and \
           packet.haslayer(Raw) and b"GET" in packet[Raw].load


def sniff_email(packet):
    """Help function for scapy.sniff() to sort while sniffing mail
    :param packet: packet received
    :type packet: scapy.packet.Packet
    :return: If the packet:
        contains TCP and port 25 (SMTP port)
    :rtype: bool"""
    return packet.haslayer(TCP) and (packet[TCP].sport == 25 or packet[TCP].dport == 25)


# special sniffer
def sniff_with_in_between_timeout(packet_filter, packet_handler, timeout):
    """The function is controlling that no more than given time passes in between the packeges
    :param packet_filter: function-filter for the packet receiver
    :type packet_filter: func
    :param packet_handler: function-printer for messages in between of searching
    :type packet_handler: func
    :param timeout: timer for second in between the packets
    :type timeout: int
    :return: nothing
    :rtype: None"""
    sniffer = AsyncSniffer(lfilter=packet_filter, prn=None, store=False)  # special sniffer
    last_seen = [time.time()]  # time when packet was received

    def wrapped_handler(pkt):  # printing and renewing the time
        packet_handler(pkt)
        last_seen[0] = time.time()

    sniffer.prn = wrapped_handler
    sniffer.start()

    try:
        while True:
            time.sleep(0.2)  # clearing CPU usage
            if time.time() - last_seen[0] > timeout:  # checking timeout
                print(f"\n!_! -> No packets received for {timeout} seconds. Sniffing stopped :]")
                break
    except KeyboardInterrupt:  # Ctrl+C
        print("\n!_! -> Sniffing stopped :]")
    sniffer.stop()  # stop sniffing, so no leaking


# Easy accessibility :]
functions = {
    '0': (None, None, None, -1, None),
    '1': ('DNS', sniff_dns, print_dns_results, 10, 'Tip: to check it faster use nslookup (mine or in CMD)'),
    '2': ('Forecast', sniff_weather, print_weather_results, 15, 'Tip: open WeatherClient and make few requests'),
    '3': ('HTTP', sniff_http, print_http_results, 10, 'Tip: open http:// site, like http://web.simmons.edu/~grovesd/comm244/notes/week2/links'),
    '4': ('E-mails', sniff_email, print_smtp_results, 20, 'Tip: use telnet or my code and create a SMTP message (using Localhost)')
}


def main():
    print('Welcome to SweetShark!')  # Welcome :]

    attributes = functions[receive_choice()]
    while attributes[0]:
        print(attributes[4], '\n---------------')
        # try:
        #     sniff(store=False, timeout=attributes[3], lfilter=attributes[1], prn=attributes[2])  # for total timeout
        # except KeyboardInterrupt:   # Ctrl+C detection :]
        #     print("\n!_! -> Sniffing stopped :]")
        sniff_with_in_between_timeout(attributes[1], attributes[2], attributes[3])
        attributes = functions[receive_choice()]  # renewing

    printf('\n\nHope to see you again!')


if __name__ == "__main__":
    main()
