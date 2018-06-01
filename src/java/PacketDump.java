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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

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

    // packets count
    private static final String COUNT_KEY = "count";
    private static final int COUNT
            = Integer.getInteger(COUNT_KEY, Integer.MAX_VALUE);

    // run in quiet mode
    private static final String QUIET_KEY = "quiet";
    private static final boolean QUIET = Boolean.getBoolean(QUIET_KEY); // default is false

    // interface
    private static final String INTF_KEY = "intf";
    private static final String INTF = System.getProperty(INTF_KEY, "");

    // how long to run in seconds
    private static final String RUN_KEY = "run";
    private static final int RUN = Integer.getInteger(RUN_KEY, 120);

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

    static void usage() {
        System.out.println("============Usage=============");
        System.out.println("You can set other attributes as -D:");
        System.out.println(String.format("\t%-20s -> %s", COUNT_KEY, "Packets numbers. Not supported Anymore. use -Drun. "));
        System.out.println(String.format("\t%-20s -> %s", READ_TIMEOUT_KEY, "Read timeout in ms"));
        System.out.println(String.format("\t%-20s -> %s", SNAPLEN_KEY, "SnapLen"));
        System.out.println(String.format("\t%-20s -> %s", RUN_KEY, "How long in seconds to run"));
        System.out.println(String.format("\t%-20s -> %s", QUIET_KEY, "Run in quiet mode? if it's true, you should set the - " + INTF_KEY));
        System.out.println(String.format("\t%-20s -> %s", INTF_KEY, "Set the network interface"));
        System.out.println(String.format("\t%-20s -> %s", PCAP_FILE_KEY, "Set the output file path"));
        System.out.println("============Usage=============\n\n");
    }
    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        String filter = args.length != 0 ? args[0] : "";
        if (filter.isEmpty()) {
            System.out.println("You Should set the filter expression as the first argument");
            System.out.println("The filter expression is same with the capture filter in the Wireshark or tcpdump");
            usage();
            return;
        }

        if (System.getProperty("quiet") == null) {
            System.out.println("Must set whether this is in a quiet mode. use -Dquiet=true|false");
            usage();
            return;
        }



        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
        System.out.println(TIMESTAMP_PRECISION_NANO_KEY + ": " + TIMESTAMP_PRECISION_NANO);
        System.out.println(RUN_KEY + ": " + RUN);
        System.out.println(QUIET_KEY + ": " + QUIET);
        System.out.println(INTF_KEY + ": " + INTF);
        System.out.println("Filter is " + filter);
        System.out.println("\n");

        // select the nifs
        PcapNetworkInterface nif;

        if (QUIET) {
            nif = _getNifByName(INTF);
        }
        else {
            if (INTF.isEmpty()) {
                try {
                    nif = _selectNif();
                }
                catch (Exception e) {
                    e.printStackTrace();
                    return;
                }
            }
            else {
                nif = _getNifByName(INTF);
            }
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

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PcapDumper> dumperAtomicReference = new AtomicReference<>();
        Thread dumpThread = new Thread(new Runnable() {
            @Override
            public void run() {
                PcapDumper dumper = null;
                int num = 0;
                try {
                    dumper = handle.dumpOpen(PCAP_FILE);
                    dumperAtomicReference.set(dumper);
                    while (!Thread.interrupted()) {
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
                }
                catch(Exception e) {
                    e.printStackTrace();
                }
                finally {
                    if (dumper != null) {
                        try {
                            dumper.close();
                        } catch (Exception e){}
                    }
                    try {
                        handle.close();
                    } catch (Exception e){}
                    latch.countDown();
                }
            }
        });
        dumpThread.start();
        try {
            latch.await(RUN, TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
        }
        finally {
            dumpThread.interrupt();
            PcapDumper dumper = dumperAtomicReference.get();
            if (dumper != null) {
                try {
                    dumper.close();
                } catch (Exception e){}
            }
            try {
                handle.close();
            } catch (Exception e){}
        }

    }


    private static PcapNetworkInterface _selectNif() throws Exception {
        List<PcapNetworkInterface> allDevs = _getAllNifs();
        _listAllNifs();
        int nifIdx = 0;
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

    private static List<PcapNetworkInterface> _getAllNifs() throws IOException {
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
        return allDevs;
    }

    private static PcapNetworkInterface _getNifByName(String name) throws IOException {
        StringBuilder allNames = new StringBuilder();

        for (PcapNetworkInterface i : _getAllNifs()) {
            allNames.append(i.getName()).append(";");
            if (i.getName().equals(name)) {
                return i;
            }
        }
        _listAllNifs();
        throw new IllegalArgumentException("Please choose one interface from above names. Unknown interface - " + name);
    }

    private static void _listAllNifs() throws IOException {
        List<PcapNetworkInterface> allDevs = _getAllNifs();
        StringBuilder sb = new StringBuilder();
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
    }

}
