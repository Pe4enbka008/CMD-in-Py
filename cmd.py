from nslookup import lookup
from ping_pong import ping
from tracert import trace
import sys


def get_value(msg):
    """Gets correct user's input - not an empty line. Adds '.com' if no '.' found.
    :param msg: message to print to the user
    :type msg: str
    :return: user's input (possibly corrected)
    :rtype: str"""
    value = input(msg).rstrip()
    while value == '':
        value = input(msg).rstrip()
    if '.' not in value and not value.replace('.', '').isdigit():
        value += '.com'
    return value


commands = ('ping', 'tracert', 'traceroute', 'nslookup', 'ns')


def exercise_command(command, value):
    """Calls correct function
    :param command: command to call
    :type command: str
    :param value: domain's IP or name
    :type value: str
    :return: nothing
    :rtype: None"""
    if command not in commands:
        print(f"Incorrect command!\nUse one of these: {', '.join(list(commands))}")
        return

    if command == 'ping':
        ping(value)
    elif command == 'tracert' or command == 'traceroute':
        trace(value)
    elif command == 'nslookup' or command == 'ns':
        ips = lookup(value)
        if ips:
            print(f"'{value}' IPs: {', '.join(ips)}")
        else:
            print(f"No IPs found for '{value}'")


def main():
    print("Welcome the 'Cookie CMD', dorry for inconvenience :]\n")
    if len(sys.argv) == 3:
        exercise_command(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:
        exercise_command(sys.argv[1], get_value('IP or domain name:  '))
    else:
        exit_word = 'exit'
        command = get_value(f'Commands: {", ".join(list(commands))}, {exit_word}:  ')[:-4]  # cut put .com
        while command != exit_word:
            while command not in commands:
                print(f"Incorrect command!")
                command = get_value(f'Commands: {", ".join(list(commands))}, {exit_word}:  ')[:-4]  # cut put .com

            exercise_command(command, get_value('IP or domain name:  '))
            print()  # spacer
            command = get_value(f'Commands: {", ".join(list(commands))}, {exit_word}:  ')[:-4]  # cut put .com

    print("\nUsage examples:")
    print("  python cmd.py <command>")
    print("  python cmd.py <command> <domain/ip>")


if __name__ == '__main__':
    main()
