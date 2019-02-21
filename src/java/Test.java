
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

        // list all interfaces....
        MacAddressHelper.getInstance().getLocalInterfaces().forEach(l -> System.out.println("Found interface " + l));
        if (args.length > 0) {
            MacAddress address = MacAddressHelper.getInstance().getMacAddress(Inet4Address.getByName(args[0]));
            System.out.println(String.format("ip=%s, mac=%s", args[0], address));
        }
        MacAddressHelper.getInstance().shutdown();
    }
}
