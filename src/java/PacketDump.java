import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

/**
 * dump packets
 */
public class PacketDump {

    private static final String COUNT_KEY= "count";
    private static final int COUNT
            = Integer.getInteger(COUNT_KEY, 5);

    private static final String READ_TIMEOUT_KEY = "readTimeout";
    private static final int READ_TIMEOUT
            = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = "snaplen";
    private static final int SNAPLEN
            = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final String TIMESTAMP_PRECISION_NANO_KEY = "timestampPrecision.nano";
    private static final boolean TIMESTAMP_PRECISION_NANO
            = Boolean.getBoolean(TIMESTAMP_PRECISION_NANO_KEY);

    private static final String PCAP_FILE_KEY = "pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "Dump.pcap");

    private PacketDump() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filter = args.length != 0 ? args[0] : "";

        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
        System.out.println("\n");

        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        }
        catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        PcapHandle.Builder phb
                = new PcapHandle.Builder(nif.getName())
                .snaplen(SNAPLEN)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(READ_TIMEOUT);
        if (TIMESTAMP_PRECISION_NANO) {
            phb.timestampPrecision(PcapHandle.TimestampPrecision.NANO);
        }
        PcapHandle handle = phb.build();

        handle.setFilter(
                filter,
                BpfProgram.BpfCompileMode.OPTIMIZE
        );

        int num = 0;
        PcapDumper dumper = handle.dumpOpen(PCAP_FILE);
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                continue;
            }
            else {
                dumper.dump(packet, handle.getTimestamp());
                num++;
                if (num >= COUNT) {
                    break;
                }
            }
        }

        dumper.close();
        handle.close();
    }

}
