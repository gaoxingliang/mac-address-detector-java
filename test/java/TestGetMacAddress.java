//import org.pcap4j.core.PcapNetworkInterface;
//import org.pcap4j.util.MacAddress;
//
//import java.net.Inet6Address;
//import java.net.InetAddress;
//import java.util.List;
//
///**
// * Created by edward.gao on 11/09/2017.
// */
//public class TestGetMacAddress {
//    public static void main(String[] args) throws Exception {
//
//
////        Inet6Address inet6Address = (Inet6Address) Inet6Address.getByName("fe80:0:0:0:250:56ff:febc:2688");
////        //"fe80:0:0:0:250:56ff:febc:2688" -> "FF02::1:FFbc:2688"
////        byte[] ipInBytes = inet6Address.getAddress();
////        byte[] broadcaseIpAddress = new byte[ipInBytes.length];
////
////        System.arraycopy(MacAddressHelper.getINSTANCE()._IPv6_BROADCAST_IPADDRESS_PREFIX, 0, broadcaseIpAddress, 0, MacAddressHelper
////                ._INSTANCE._IPv6_BROADCAST_IPADDRESS_PREFIX.length);
////        System.arraycopy(ipInBytes, ipInBytes.length - 3, broadcaseIpAddress, MacAddressHelper._INSTANCE._IPv6_BROADCAST_IPADDRESS_PREFIX
////                .length - 3, 3);
////
////        System.out.println(Inet6Address.getByAddress(broadcaseIpAddress));
////
////        System.out.println(MacAddressHelper._INSTANCE._getBroadcastMacAddress4IPv6(inet6Address));
////
////        //System.exit(1);
//
//        List<PcapNetworkInterface> _local = MacAddressHelper.getInstance().getLocalInterfaces();
//        _local.forEach(l -> System.out.println(l));
//
//        String[] testIps = {"127.0.0.1", "10.130.11.155" , "192.168.170.149", "10.0.0.1", "10.130.11.57", "10.130.11.50"};
//        if (args != null && args.length > 0) {
//            testIps = args[0].split(",");
//        }
//        for (String testIp : testIps) {
//            long start = System.currentTimeMillis();
//            PcapNetworkInterface i = MacAddressHelper.getInstance().
//                    _selectSuitableNetworkInterface(InetAddress.getByName(testIp))._selectedNetworkInterface;
//            System.out.println("Matched " + testIp + " is " + i);
//
//            MacAddress address = MacAddressHelper.getInstance().getMacAddress(InetAddress.getByName(testIp));
//            System.out.println(String.format("Related mac address for ip %s is %s costTime(ms)=%d", testIp, address, System
//                    .currentTimeMillis() - start));
//
//        }
//
//        MacAddressHelper._INSTANCE.shutdown();
//    }
//}
