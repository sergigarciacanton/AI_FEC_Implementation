import time
from pyaccesspoint.PyAccessPoint import pyaccesspoint
import os

access_point = pyaccesspoint.AccessPoint(wlan='wlan0', ssid='Test301', password='1234567890',
                                         ip='10.0.0.1', netmask='255.255.255.0')


def stop(enter, wireshark_if, tshark_if):
    if enter:
        if wireshark_if == "y" or wireshark_if == "":
            os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
        if tshark_if == "y" or tshark_if == "":
            os.system("sudo screen -S ap-tshark -X stuff '^C\n'")
    else:
        try:
            if wireshark_if == "y" or wireshark_if == "":
                os.system("sudo screen -S ap-wireshark -X stuff '^C\n'")
        except:
            pass
        try:
            if tshark_if == "y" or tshark_if == "":
                os.system("sudo screen -S ap-tshark -X stuff '^C\n'")
        except:
            pass


def main():
    tshark_if = 'n'
    wireshark_if = 'n'
    try:
        script_path = os.path.dirname(os.path.realpath(__file__))
        script_path = script_path + "/"
        os.system("sudo mkdir " + script_path + "logs > /dev/null 2>&1")
        os.system("sudo chmod 777 " + script_path + "logs")
        # UPDATE QUESTION
        update = input("[?] Install/Update dependencies? Y/n: ")
        update = update.lower()
        if update == "y" or update == "":
            print("[I] Checking/Installing dependencies, please wait...")
            os.system("sudo apt-get update")
            os.system("sudo apt-get install dnsmasq -y")
            os.system("sudo apt-get install wireshark -y")
            os.system("sudo apt-get install hostapd -y")
            os.system("sudo apt-get install screen -y")
            os.system("sudo apt-get install python-pip -y")
            os.system("sudo apt-get install python3-pip -y")
            os.system("sudo apt-get install python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev "
                      "libjpeg62-turbo-dev zlib1g-dev -y")
            os.system("sudo apt-get install libpcap-dev -y")
            os.system("sudo python -m pip install pcapy")
        # /UPDATE QUESTION

        # WIRESHARK & TSHARK QUESTION
        wireshark_if = input("[?] Start WIRESHARK on wlan0? Y/n: ")
        wireshark_if = wireshark_if.lower()
        if wireshark_if != "y" and wireshark_if != "":
            tshark_if = input("[?] Capture packets to .pcap with TSHARK? (no gui needed) Y/n: ")
            tshark_if = tshark_if.lower()
        # /WIRESHARK & TSHARK QUESTION

        # START AP
        print("[I] Starting AP on wlan0...")
        access_point.start()
        if wireshark_if == "y" or wireshark_if == "":
            print("[I] Starting WIRESHARK...")
            os.system("sudo screen -S ap-wireshark -m -d wireshark -i wlan0 -k -w " + script_path +
                      "logs/ap-wireshark.pcap")
        if tshark_if == "y" or tshark_if == "":
            print("[I] Starting TSHARK...")
            os.system("sudo screen -S ap-tshark -m -d tshark -i wlan0 -w " + script_path +
                      "logs/ap-tshark.pcap")
        # /START AP

        time.sleep(5)

        input("[*] Press Enter to stop...")

        # STOP
        print("")
        print("[!] Stopping...")
        access_point.stop()
        stop(True, wireshark_if, tshark_if)
        print("[I] Traffic have been saved to the 'log' folder!")
        print("[I] AP stopped.")
        # /STOP
    except KeyboardInterrupt:
        print("\n\n[!] Stopping... (Dont worry if you get errors)")
        access_point.stop()
        stop(False, wireshark_if, tshark_if)
        print("[I] AP stopped.")


if __name__ == '__main__':
    main()
