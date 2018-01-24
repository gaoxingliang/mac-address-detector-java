
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;

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
        // list all interfaces....
        MacAddressHelper.getInstance().getLocalInterfaces().forEach(l -> System.out.println("Found interface " + l));
        if (args.length > 0) {
            MacAddress address = MacAddressHelper.getInstance().getMacAddress(Inet4Address.getByName(args[0]));
            System.out.println(String.format("ip=%s, mac=%s", args[0], address));
        }
        MacAddressHelper.getInstance().shutdown();
    }
}
