#Abstract
This page will describe how to build a libpcap.<br>
I also uploaded the latest 1.8.1 release files under directory <b>libpcapfiles</b> for you to test quickly<br>
#Linux
`wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz`<br>
`tar -xvzf libpcap-1.8.1.tar.gz`<br>
`yum install flex bison`<br>
`./configure`<br>
`make`<br>
Then the file is <b>libpcap.so.1.8.1</b> under same directory, rename this to libpcap.so or libpcap64.so<br>

#Windows
For windows, I used the <a href="https://nmap.org/npcap/">npcap</a> to do the lower layer packet sending and process.
Download those libs from https://nmap.org/npcap/  sdk files.

#MacOS
`wget http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz`<br>
`tar -xvzf libpcap-1.8.1.tar.gz`<br>
`./configure`<br>
`make`<br>
Then the file is <b>libpcap.1.8.1.dylib</b> under same directory
