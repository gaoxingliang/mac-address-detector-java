import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.LinkLayerAddress;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * dump packets
 * Copy from pcap4j examples
 * The filter syntax is - https://biot.com/capstats/bpf.html
 * <p>
 * When it's working for dns, you may got an IllegalArgumentException,
 * Which fixed in here: https://github.com/kaitoy/pcap4j/issues/123
 */
public class PacketDump {

    private static final String LINE_SEPARATOR = "\n";

    private static final String COUNT_KEY = "count";
    private static final int COUNT
            = Integer.getInteger(COUNT_KEY, 1000);

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
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HH_mm_ss");

    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "Dump" + sdf.format(new Date()) + ".pcap");


    private PacketDump() {
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        String filter = args.length != 0 ? args[0] : "";
        if (filter.isEmpty()) {
            System.out.println("You Should set the filter expression as the first argument");
            System.out.println("The filter expression is same with the capture filter in the Wireshark or tcpdump");
            System.out.println("You can set other attributes as -D:");
            System.out.println(String.format("\t%-20s -> %s", COUNT_KEY, "Packets numbers"));
            System.out.println(String.format("\t%-20s -> %s", READ_TIMEOUT_KEY, "Read timeout in ms"));
            System.out.println(String.format("\t%-20s -> %s", SNAPLEN_KEY, "SnapLen"));
            return;
        }


        System.out.println(COUNT_KEY + ": " + COUNT);
        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
        System.out.println("\n");


        // select the nifs

        PcapNetworkInterface nif;
        try {
            nif = _selectNif();
        }
        catch (Exception e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            System.out.println("No interfaces found, make sure your set the correct libpcap files");
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

        // add one shutdownhook to print the output file
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            File dumpfile = new File(PCAP_FILE);
            try {
                if (dumpfile.exists()) {
                    System.out.println("Output file is - " + dumpfile.getCanonicalPath());
                }
                else {
                    System.out.println("Dump file not existed - " + dumpfile.getCanonicalPath());
                }
            } catch (IOException e) {}
        }));

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


    private static PcapNetworkInterface _selectNif() throws Exception {
        List<PcapNetworkInterface> allDevs = null;
        try {
            allDevs = Pcaps.findAllDevs();
        }
        catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }

        if (allDevs == null || allDevs.isEmpty()) {
            throw new IOException("No NIF found, is the libpcap successfully set/installed?");
        }
        StringBuilder sb = new StringBuilder(200);
        int nifIdx = 0;
        for (PcapNetworkInterface nif : allDevs) {
            sb.append("NIF[").append(nifIdx).append("]: ")
                    .append(nif.getName()).append(LINE_SEPARATOR);

            if (nif.getDescription() != null) {
                sb.append("      : description: ")
                        .append(nif.getDescription()).append(LINE_SEPARATOR);
            }

            for (LinkLayerAddress addr : nif.getLinkLayerAddresses()) {
                sb.append("      : link layer address: ")
                        .append(addr).append(LINE_SEPARATOR);
            }

            for (PcapAddress addr : nif.getAddresses()) {
                sb.append("      : address: ")
                        .append(addr.getAddress()).append(LINE_SEPARATOR);
            }
            sb.append(LINE_SEPARATOR).append(LINE_SEPARATOR);
            nifIdx++;
        }
        sb.append(LINE_SEPARATOR);
        System.out.println(sb.toString());

        while (true) {
            write(String.format("Select a device number ( 0 - %d) to capture packets, or enter 'q' to quit > ", allDevs.size() - 1));
            String input;
            if ((input = read()) == null) {
                continue;
            }

            if (input.equals("q")) {
                return null;
            }

            try {
                nifIdx = Integer.parseInt(input);
                if (nifIdx < 0 || nifIdx >= allDevs.size()) {
                    write("Invalid input." + LINE_SEPARATOR);
                    continue;
                }
                else {
                    break;
                }
            }
            catch (NumberFormatException e) {
                write("Invalid input." + LINE_SEPARATOR);
                continue;
            }
        }

        return allDevs.get(nifIdx);

    }


    /**
     * @param msg msg
     * @throws IOException if fails to write.
     */
    protected static void write(String msg) throws IOException {
        System.out.print(msg);
    }

    /**
     * @return string
     * @throws IOException if fails to read.
     */
    protected static String read() throws IOException {
        BufferedReader reader
                = new BufferedReader(new InputStreamReader(System.in));
        return reader.readLine();
    }

}
