
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IcmpV6NeighborSolicitationPacket;
import org.pcap4j.packet.IpV6NeighborDiscoverySourceLinkLayerAddressOption;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV6Code;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Detect a mac address
 * The main logic is:
 * 0) set the filter
 * 1) compose the packet
 * 2) start the receive thread task
 * 3) send tha packet
 * 4) wait response task result or timeout happen
 * <p>
 * Created by edward.gao on 10/09/2017.
 */
public class MacAddressHelper {

    private static final String _KEY_READTIMEOUT_IN_MILLS = "macaddress.readTimeout.mills";
    private static final String _KEY_RECEIVETIMEOUT_IN_MILLS = "macaddress.receiveTimeout.mills";
    private static final String _KEY_SEND_RECEIVE_THREADS = "macaddress.sendreceive.threads";
    private static final String _KEY_WAIT_RECEIVE_START_IN_MILLS = "macaddress.waitStartedRunning.mills";

    private List<PcapNetworkInterface> _localPcapNetworkInterfaces = null;
    private Map<InetAddress, MacAddress> _localAddresse2MacAddress = null;
    private byte[] _IPv6_BROADCAST_IPADDRESS_PREFIX = null;
    private byte[] _IPv6_BROADCAST_MACADDRESS_PREFIX = null;

    private boolean _initted = false;

    private Throwable _initError = null;

    /**
     * NOTICE, the pcap will block for those time even when the data returned....
     */
    private int _readTimeoutInMillSeconds = 100; // 100 ms for reading a response from the packet
    private int _waitResponseTimeoutInMillSeconds = 2000; // 2 second, this should be quick enough under same switch

    // wait till the receive task started running, this should not be too large
    private int _waitReceiveTaskStartRunningInSeconds = 5000;

    private ScheduledExecutorService _executor; // send and receive thread pool
    private int _threadCount = 10; //  send and receive thread pool count
    private int _snapLen = 65535;
    private int _sendPacketCount = 1;


    static {
        // for linux, only required libpcap, so you see the filename is with version
        // for windows, we need Packet.dll and wpcap.dll, and wpcap required Packet.dll so the filename is WITHOUT version
        String pcapLibKey = "org.pcap4j.core.pcapLibName";
        String packetDllKey = "org.pcap4j.core.packetLibName";
//        if (Environment.isLinux()) {
//            System.setProperty(pcapLibKey, Paths.get(".", "lib", Environment.is64BitOS() ? "libpcap64.so" : "libpcap.so")
//                    .toString());
//        }
//        else {
//            System.setProperty(packetDllKey, Paths.get(Environment.root, "lib", "Packet.dll").toString());
//            System.setProperty(pcapLibKey, Paths.get(Environment.root, "lib", "wpcap.dll").toString());
//        }
//        System.out.println(String.format("Pcap related conf set %s=%s, (for windows) %s=%s", pcapLibKey, System.getProperty(pcapLibKey),
//                packetDllKey, System.getProperty(packetDllKey)));
    }

    private MacAddressHelper() {
        try {

            _localPcapNetworkInterfaces = Pcaps.findAllDevs();
            _executor = Executors.newScheduledThreadPool(_threadCount);
            _IPv6_BROADCAST_IPADDRESS_PREFIX = Inet6Address.getByName("FF02::1:FF00:0000").getAddress();
            _IPv6_BROADCAST_MACADDRESS_PREFIX = MacAddress.getByName("33:33:ff:00:00:00").getAddress();
            _localAddresse2MacAddress = new HashMap<>();

            Enumeration<NetworkInterface> localNetworkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (localNetworkInterfaces.hasMoreElements()) {
                NetworkInterface nwInterface = localNetworkInterfaces.nextElement();
                byte[] mac = nwInterface.getHardwareAddress();
                Enumeration<InetAddress> addresses = nwInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress currentIp = addresses.nextElement();
                    if (mac == null) {
                        System.out.println("Can't find mac address for local ip=" + currentIp);
                        _localAddresse2MacAddress.put(currentIp, null);
                    }
                    else {
                        // although jdk said, the returned value is a mac address, but actually this may fail on some local mac address
                        // the length is NOT 6 bytes
                        if (mac.length != MacAddress.SIZE_IN_BYTES) {
                            _localAddresse2MacAddress.put(currentIp, null);
                            System.out.println(String.format("Found invalid mac address ip=%s,mac=%s", currentIp, ByteArrays.toHexString(mac,
                                    ":")));
                        }
                        else {
                            _localAddresse2MacAddress.put(currentIp, MacAddress.getByAddress(mac));
                        }
                    }

                }
            }
            System.out.println(String.format("Mac Address helper init done localips=%d, threadPool=%d, readTimeout(ms)=%d, waitResponse(ms)" +
                            "=%d, waitReceiveTaskStart(ms)=%d",
                    _localAddresse2MacAddress.size(), _threadCount,
                    _readTimeoutInMillSeconds, _waitResponseTimeoutInMillSeconds, _waitReceiveTaskStartRunningInSeconds));
            _initted = true;
        }
        catch (Throwable e) {
            _initError = e;
        }
    }

    public static MacAddressHelper getInstance() {
        return MacAddressHelperHolder._INSTANCE;
    }

    public List<PcapNetworkInterface> getLocalInterfaces() {
        if (!_initted) {
            throw new IllegalStateException("Fail to init component", _initError);
        }
        return _localPcapNetworkInterfaces;
    }

    public MacAddress getMacAddress(InetAddress address) {
        if (address == null) {
            throw new IllegalArgumentException("Address is null");
        }
        if (!_initted) {
            throw new IllegalStateException("Fail to init component", _initError);
        }
        if (_localAddresse2MacAddress.containsKey(address)) {
            return _localAddresse2MacAddress.get(address);
        }
        try {
            return _getMacAddress(address);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void shutdown() {
        if (_executor != null) {
            _executor.shutdown();
        }
    }

    /**
     * get the remote mac address for a ip v4 address
     *
     * @param inetAddress
     * @return
     * @throws PcapNativeException
     * @throws NotOpenException
     * @throws InterruptedException
     */
    private MacAddress _getMacAddress(InetAddress inetAddress) throws PcapNativeException, NotOpenException, InterruptedException,
            UnknownHostException {

        SelectedInterface intf = _selectSuitableNetworkInterface(inetAddress);
        if (intf._selectedNetworkInterface == null) {
            throw new IllegalStateException("Can't find interface for address " + inetAddress);
        }


        MacAddress localMacAddress = MacAddress.getByAddress(intf._selectedNetworkInterface.getLinkLayerAddresses().get(0).getAddress());
        InetAddress localIpAddress = intf._selectedIpAddress;

        PcapHandle receiveHandle = null;
        PcapHandle sendHandle = null;
        final AtomicReference<MacAddress> remoteMacAddress = new AtomicReference<>();
        final boolean isIPv4Address = inetAddress instanceof Inet4Address;
        try {

            receiveHandle
                    = intf._selectedNetworkInterface.openLive(_snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    _readTimeoutInMillSeconds);


            String filter = isIPv4Address ? _getFilter4IPv4(inetAddress, localMacAddress, localIpAddress) :
                    _getFilter4IPv6((Inet6Address) inetAddress, localMacAddress, (Inet6Address) localIpAddress);
            System.out.println("receive filter set filter=" + filter);


            receiveHandle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);


            sendHandle
                    = intf._selectedNetworkInterface.openLive(_snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    _readTimeoutInMillSeconds);
            PacketListener listener = (packet) -> {
                System.out.println("Packet received" + packet.toString());
                if (isIPv4Address && packet.contains(ArpPacket.class)) {
                    ArpPacket arp = packet.get(ArpPacket.class);
                    if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                        remoteMacAddress.set(arp.getHeader().getSrcHardwareAddr());
                    }
                }
                else if (!isIPv4Address && packet.contains(EthernetPacket.class)) {
                    EthernetPacket ns = packet.get(EthernetPacket.class);
                    remoteMacAddress.set(ns.getHeader().getSrcAddr());
                }
            };

            CyclicBarrier cyclicBarrier = new CyclicBarrier(2);

            ReceiveTask receiveTask = new ReceiveTask(receiveHandle, listener, cyclicBarrier);
            Future receiveFuture = _executor.submit(receiveTask);

            EthernetPacket.Builder etherBuilder = isIPv4Address ? _getPacketBuilder4IPv4(inetAddress, localMacAddress, localIpAddress) :
                    _getPacketBuilder4IPv6((Inet6Address) inetAddress, localMacAddress, (Inet6Address) localIpAddress);
            Packet p = etherBuilder.build();
            try {
                cyclicBarrier.await(_waitReceiveTaskStartRunningInSeconds, TimeUnit.MILLISECONDS);
            }
            catch (BrokenBarrierException | TimeoutException e) {
                e.printStackTrace();
                return remoteMacAddress.get();
            }
            sendHandle.sendPacket(p);
            try {
                receiveFuture.get(_waitResponseTimeoutInMillSeconds, TimeUnit.MILLISECONDS);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            return remoteMacAddress.get();
        }
        finally {
            _closeHandle(receiveHandle);
            _closeHandle(sendHandle);
        }
    }

    private String _getFilter4IPv4(InetAddress remoteAddress, MacAddress localMacAddress, InetAddress localIpAdress) {
        return String.format("arp and src host %s and dst host %s and ether dst %s",
                remoteAddress.getHostAddress(),
                localIpAdress.getHostAddress(),
                Pcaps.toBpfString(localMacAddress));
    }

    private String _removePercentInIPv6Address(String ipv6Address) {
        int index = ipv6Address.indexOf("%");
        if (index > 0) {
            return ipv6Address.substring(0, index);
        }
        return ipv6Address;
    }


    private String _getFilter4IPv6(Inet6Address remoteAddress, MacAddress localMacAddress, Inet6Address localIpAdress) {
        return String.format("icmp6 and src host %s and dst host %s and ether dst %s",
                _removePercentInIPv6Address(remoteAddress.getHostAddress()),
                _removePercentInIPv6Address(localIpAdress.getHostAddress()),
                Pcaps.toBpfString(localMacAddress));
    }


    private EthernetPacket.Builder _getPacketBuilder4IPv4(InetAddress remoteAddress, MacAddress localMacAddress, InetAddress
            localIpAdress) {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .srcHardwareAddr(localMacAddress)
                .srcProtocolAddr(localIpAdress)
                .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .operation(ArpOperation.REQUEST)
                .dstProtocolAddr(remoteAddress);


        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(localMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        return etherBuilder;
    }


    private EthernetPacket.Builder _getPacketBuilder4IPv6(Inet6Address remoteAddress, MacAddress localMacAddress, Inet6Address
            localIpAdress) throws UnknownHostException {
        MacAddress broadcastMacAddress = _getBroadcastMacAddress4IPv6(remoteAddress);
        Inet6Address broadcasetIPAddress = _getBroadcastIPAddress4IPv6(remoteAddress);

        IcmpV6NeighborSolicitationPacket.Builder v6Builder = new IcmpV6NeighborSolicitationPacket.Builder();
        v6Builder.targetAddress(remoteAddress);
        v6Builder.reserved(0);
        IpV6NeighborDiscoverySourceLinkLayerAddressOption.Builder optionBuilder = new IpV6NeighborDiscoverySourceLinkLayerAddressOption
                .Builder();
        IpV6NeighborDiscoverySourceLinkLayerAddressOption option = optionBuilder
                .linkLayerAddress(localMacAddress.getAddress())
                .correctLengthAtBuild(true)
                .build();
        List<IcmpV6CommonPacket.IpV6NeighborDiscoveryOption> options = new ArrayList<>();
        options.add(option);
        v6Builder.options(options);


        IcmpV6CommonPacket.Builder icmpV6b = new IcmpV6CommonPacket.Builder();
        icmpV6b.type(IcmpV6Type.NEIGHBOR_SOLICITATION)
                .code(IcmpV6Code.NO_CODE)
                .srcAddr(localIpAdress)
                .dstAddr(broadcasetIPAddress)
                .payloadBuilder(v6Builder)
                .correctChecksumAtBuild(true);


        IpV6Packet.Builder ipv6b = new IpV6Packet.Builder();
        ipv6b.version(IpVersion.IPV6)
                .trafficClass(IpV6SimpleTrafficClass.newInstance((byte) 0x12))
                .flowLabel(IpV6SimpleFlowLabel.newInstance(0))
                .nextHeader(IpNumber.ICMPV6)
                .hopLimit((byte) 255)
                .srcAddr(localIpAdress)
                .dstAddr(broadcasetIPAddress) // "fe80:0:0:0:250:56ff:febc:2688" -> "FF02::1:FFbc:2688"
                .correctLengthAtBuild(true)
                .payloadBuilder(icmpV6b);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder.dstAddr(broadcastMacAddress)
                .srcAddr(localMacAddress)
                .type(EtherType.IPV6)
                .payloadBuilder(ipv6b)
                .paddingAtBuild(true);

        return etherBuilder;
    }


    private void _closeHandle(PcapHandle handle) {
        if (handle != null) {
            try {
                handle.breakLoop();
            }
            catch (Exception e) {
            }
            try {
                handle.close();
            }
            catch (Exception e) {

            }
        }
    }

    /**
     * select a most suitable network interface according to the address
     *
     * @param address
     * @return
     */
    private SelectedInterface _selectSuitableNetworkInterface(InetAddress address) {
        int similiarBytes = Integer.MIN_VALUE;
        SelectedInterface selectedInterface = new SelectedInterface();

        byte[] inputIpInBytes = address.getAddress();
        for (PcapNetworkInterface currentInterface : _localPcapNetworkInterfaces) {
            List<PcapAddress> addresses = currentInterface.getAddresses();

            if (addresses != null) {
                for (PcapAddress ipAddress : addresses) {
                    // make sure the address should be same type, all ipv4 or all ipv6
                    if (!_isSameTypeAddress(address, ipAddress.getAddress())) {
                        continue;
                    }

                    // we also need to make sure they are under same netmask
                    // because in some cases, a router may return an external arp protocol
                    // this worked for ipv4 and ipv6
                    InetAddress maskAddr = ipAddress.getNetmask();
                    if (maskAddr != null
                            && !_isUnderSameSubNet(address, ipAddress.getAddress(), maskAddr)) {
                        continue;
                    }

                    byte[] ipInBytes = ipAddress.getAddress().getAddress();
                    int currentSimiliarBytes = _similarBytes(inputIpInBytes, ipInBytes);
                    if (currentSimiliarBytes > similiarBytes) {
                        selectedInterface._selectedNetworkInterface = currentInterface;
                        selectedInterface._selectedIpAddress = ipAddress.getAddress();
                        similiarBytes = currentSimiliarBytes;
                    }
                }
            }
        }
        return selectedInterface;
    }

    private boolean _isSameTypeAddress(InetAddress address1, InetAddress address2) {
        return (address1 instanceof Inet6Address && address2 instanceof Inet6Address)
                || (address1 instanceof Inet4Address && address2 instanceof Inet4Address);
    }

    private class ReceiveTask implements Runnable {

        private final PcapHandle receiveHandle;
        private final PacketListener listener;
        private final CyclicBarrier cyclicBarrier;
        private String loggerComponent, loggerId;

        public ReceiveTask(PcapHandle receiveHandle, PacketListener listener, CyclicBarrier cyclicBarrier) {
            this.receiveHandle = receiveHandle;
            this.listener = listener;
            this.cyclicBarrier = cyclicBarrier;
        }

        public void setLogger(String loggerComponent, String loggerId) {
            this.loggerComponent = loggerComponent;
            this.loggerId = loggerId;
        }

        @Override
        public void run() {
            try {
                cyclicBarrier.await();
                receiveHandle.loop(_sendPacketCount, listener);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private class SelectedInterface {
        private PcapNetworkInterface _selectedNetworkInterface;
        private InetAddress _selectedIpAddress;
    }

    private int _similarBytes(byte[] b1, byte[] b2) {
        int n = b1.length;
        int i = 0;
        for (i = 0; i < n && b1[i] == b2[i]; i++) {
        }
        return i;
    }

    static boolean _isUnderSameSubNet(InetAddress testAddr, InetAddress currentAddr, InetAddress maskAddr) {
        byte [] test = testAddr.getAddress();
        byte [] current = currentAddr.getAddress();
        byte [] mask = maskAddr.getAddress();
        boolean equal = true;
        for (int i =0; i < test.length; i++) {
            if ((test[i] & mask[i]) != (current[i] & mask[i])) {
                equal = false;
                break;
            }
        }
        return equal;
    }

    /**
     * The broadcast ip for a icmp v6 request is replaced all bytes except the last three bytes with _IPv6_BROADCAST_IPADDRESS_PREFIX
     *
     * @param inet6Address
     * @return
     */
    private Inet6Address _getBroadcastIPAddress4IPv6(Inet6Address inet6Address) throws UnknownHostException {
        //"fe80:0:0:0:250:56ff:febc:2688" -> "FF02::1:FFbc:2688"
        byte[] ipInBytes = inet6Address.getAddress();
        byte[] broadcastIpAddress = new byte[ipInBytes.length];
        System.arraycopy(_IPv6_BROADCAST_IPADDRESS_PREFIX, 0, broadcastIpAddress, 0, _IPv6_BROADCAST_IPADDRESS_PREFIX.length);
        int reservedBytes = 3;
        System.arraycopy(ipInBytes, ipInBytes.length - reservedBytes, broadcastIpAddress, _IPv6_BROADCAST_IPADDRESS_PREFIX.length -
                reservedBytes, reservedBytes);
        return (Inet6Address) Inet6Address.getByAddress(broadcastIpAddress);
    }

    /**
     * The broadcast mac address for a icmpv6 request is replaced all bytes with 33:33:ff except the last thress bytes
     * fe80::250:56ff:fe95:f8d -> 33:33:ff:95:0f:8d
     *
     * @param inet6Address
     * @return
     */
    private MacAddress _getBroadcastMacAddress4IPv6(Inet6Address inet6Address) {
        byte[] ipInBytes = inet6Address.getAddress();
        byte[] broadcastMacAddress = new byte[_IPv6_BROADCAST_MACADDRESS_PREFIX.length];
        System.arraycopy(_IPv6_BROADCAST_MACADDRESS_PREFIX, 0, broadcastMacAddress, 0, _IPv6_BROADCAST_MACADDRESS_PREFIX.length);
        int reservedBytes = 3;
        System.arraycopy(ipInBytes, ipInBytes.length - reservedBytes, broadcastMacAddress, _IPv6_BROADCAST_MACADDRESS_PREFIX.length -
                reservedBytes, reservedBytes);
        return MacAddress.getByAddress(broadcastMacAddress);
    }

    private static class MacAddressHelperHolder {
        // to make sure this is really lazy init
        // and the static block in the MacAddressHelper will run before this construction
        private static MacAddressHelper _INSTANCE = new MacAddressHelper();

        private MacAddressHelperHolder() {
        }

        public static final MacAddressHelper get() {
            return _INSTANCE;
        }
    }


    /**
     * @param args the remote device ip lists split by comma
     */
    public static void main(String[] args) {

        // check libpcap file really exists
        String libpcapKeyName = "org.pcap4j.core.pcapLibName";
        String libpcapSet = System.getProperty(libpcapKeyName);
        if (libpcapSet == null || libpcapSet.isEmpty()) {
            System.out.println(String.format("no libpcap property set, try with -D%s=YourLibPcapFile", libpcapKeyName));
            return;
        }
        File libpcapFile = new File(libpcapSet);
        if (!(libpcapFile.exists() && libpcapFile.isFile())) {
            System.out.println("libpcap file not exists " + libpcapFile.getAbsolutePath());
            return;
        }
        System.out.println("Use libpcap file - " + libpcapFile.getAbsolutePath());
        System.out.println();
        System.out.println("Version - " + Pcaps.libVersion());
        // list all interfaces
        List<PcapNetworkInterface> localInterfaces = MacAddressHelper.getInstance().getLocalInterfaces();
        System.out.println("List local interfaces");
        for (PcapNetworkInterface localIntf : localInterfaces) {
            System.out.println("\t" + localIntf);
        }

        if (args == null || args.length == 0) {
            System.out.println("No remote device ips provided. try with arguments IP1,IP2 ....");
            return;
        }
        for (String ip : args) {
            System.out.println("Start find mac for ip - " + ip);
            try {
                MacAddress mac = MacAddressHelper.getInstance().getMacAddress(InetAddress.getByName(ip));
                System.out.println("The mac is - " + mac);
            }
            catch (UnknownHostException e) {
                System.out.println("Unknown host " + ip);
                e.printStackTrace();
            }
        }

        MacAddressHelper.getInstance().shutdown();

    }

}
