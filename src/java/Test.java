
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;

/**
 * simple demo
 * Created by edward.gao on 28/09/2017.
 */
public class Test {

    /**
     * args[0] is the ip you want to detected
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        InetAddress addr1 = InetAddress.getByName("172.16.14.13");
        InetAddress addr2 = InetAddress.getByName("172.16.14.12");
        InetAddress addr3 = InetAddress.getByName("172.16.15.12");
        InetAddress mask = InetAddress.getByName("255.255.255.0");

        System.out.println(MacAddressHelper._isUnderSameSubNet(addr1, addr2, mask));
        System.out.println(MacAddressHelper._isUnderSameSubNet(addr1, addr3, mask));

        //address: [/fe80:0:0:0:1016:168a:afda:7c7b] netmask: [/ffff:ffff:ffff:ffff:0:0:0:0] broadcastAddr: [null] dstAddr [null]
        InetAddress addr1v6 = InetAddress.getByName("fe80:0:0:0:1016:168a:afda:7c7b");
        InetAddress maskv6 = InetAddress.getByName("ffff:ffff:ffff:ffff:0:0:0:0");
        InetAddress addr2v6 = InetAddress.getByName("fe80:0:0:0:1016:168a:afda:7c7e");
        InetAddress addr3v6 = InetAddress.getByName("fe80:0:0:1:1016:168a:afda:7c7e");
        System.out.println(MacAddressHelper._isUnderSameSubNet(addr1v6, addr2v6, maskv6));
        System.out.println(MacAddressHelper._isUnderSameSubNet(addr3v6, addr2v6, maskv6));


        // address: [/fe80:0:0:0:1016:168a:afda:7c7b] netmask: [/ffff:ffff:ffff:ffff:0:0:0:0] broadcastAddr: [null] dstAddr [null]


        // list all interfaces....
        MacAddressHelper.getInstance().getLocalInterfaces().forEach(l -> System.out.println("Found interface " + l));
        if (args.length > 0) {
            MacAddress address = MacAddressHelper.getInstance().getMacAddress(Inet4Address.getByName(args[0]));
            System.out.println(String.format("ip=%s, mac=%s", args[0], address));
        }
        MacAddressHelper.getInstance().shutdown();
    }
}
