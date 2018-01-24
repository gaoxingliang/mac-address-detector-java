# mac-address-detector-java
Use pcap4j to detect a mac address of remote host
# Reason
I searched the whole website, and I found no solution provided to detect a mac address of remote host under same subnetwork. <br>
<br>
So I created this project.
# Implementation
I used pcap4j to send and filtering packets. 
and for a IPv4 address, I used arp protocol related function to extract the mac address.
and for a IPv6 address, I used ndp (neighbor discovery) protocol related function to extract the mac address.


# Dependency
1. pcap4j 1.7.x<br>
2. libpcap. (ready for use version files has been uploaded into libpcapfiles)

# How to build
## Build mac-address-detector-*.jar
1. gradle build  (no dep jars included)
2. gradle fatjar (recommended, dep jars included)

## Run on linux
on linux, you can load the libpcap directly without install anything

``
java -Dorg.pcap4j.core.pcapLibName=libpcap.so -cp .:mac-address-detector-all-0.1.jar com.logicmonitor.macaddress.detector.Test 192.168.170.149
``

## Run on windows
On windows, the npcap is required to be installed. (no reboot required)

``
java -Dorg.pcap4j.core.pcapLibName=wpcap.dll -Dorg.pcap4j.core.packetLibName=Packet.dll -cp .;mac-address-detector-all-0.1.jar com.logicmonitor.macaddress.detector.Test 192.168.170.149
``


#Updates
Add a func to do packet dump by using pcap4j.
After build the jar, call the main class PacketDump.
