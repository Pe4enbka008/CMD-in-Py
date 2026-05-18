# Doesn't work :[ - 29/05/2025 - 21:39  (If I'll fix it one day, I want to date it!)
import smtplib
import threading
import time
from aiosmtpd.controller import Controller  # pip install aiosmtpd

link = ('localhost', 25)
from_address = "sender@sweet.com"
to_address = "receiver@sweet.com"
message = "HELLO!!!!!!!!"


class CustomHandler:
    async def handle_DATA(self, _server, _session, envelope):
        """This function is a custom handler that reacts to incoming emails and prints what was received
        :param _server: Info about the SMTP server
        :type _server: aiosmtpd.smtp.SMTP
        :param _session: Info about the current SMTP session
        :type _session: aiosmtpd.smtp.Session
        :param envelope: The email sent
        :type envelope: aiosmtpd.smtp.Envelope
        :return: OK code
        :rtype: str"""
        print("\n[SMTP Server] Got a message!")
        print(f"From: {envelope.mail_from}")
        print(f"To: {envelope.rcpt_tos}")
        print(f"Data:\n{envelope.content.decode()}")
        return '250 OK'


# Start server in the background
threading.Thread(
    target=lambda: Controller(CustomHandler(), hostname=link[0], port=link[1]).start(),
    daemon=True
).start()
time.sleep(1)

try:
    with smtplib.SMTP(*link) as server:
        server.sendmail(from_address, to_address, message)
        print("Email sent successfully :]")
except Exception as e:
    print(f"!_! -> Failed to send email: {e}")

time.sleep(3)
