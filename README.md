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
1. pcap4j 1.7.3<br>
2. libpcap. (ready for use version files has been uploaded into libpcapfiles)

# how to use
## 1. import this dependency
  
gradle:
```shell
implementation group: 'io.gitee.gaoxingliang', name: 'mac-address-detector-java', version: '0.0.1'
```

mvn:
```xml
<dependency>
    <groupId>io.gitee.gaoxingliang</groupId>
    <artifactId>mac-address-detector-java</artifactId>
    <version>0.0.1</version>
</dependency>
```
and use it:

```java
MacAddress address = MacAddressHelper.getInstance()
        .getMacAddress(Inet4Address.getByName("192.168.110.100"));
```

## 2.1 Use it on linux
the pre-built dep files are under `libpcapfiles` directory. <br>
on linux, you can load the libpcap directly without install anything

``
java -Dorg.pcap4j.core.pcapLibName=libpcap.so YourProgram
``

## 2.2 Use it on windows
On windows, the npcap is required to be installed. (no reboot required)

``
java -Dorg.pcap4j.core.pcapLibName=wpcap.dll -Dorg.pcap4j.core.packetLibName=Packet.dll YourProgram
``

# Changes 
## 09-06-2024

## 01-24-2018
Add a func to do packet dump by using pcap4j.
After build the jar, call the main class PacketDump.
``
java -Dorg.pcap4j.core.pcapLibName=libpcap.so -cp .:networkutils-all-0.2.jar PacketDump "udp"
``