package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.io.BufferedReader;
import java.io.FileReader;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.net.Socket;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.OutputStreamWriter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IExtensionStateListener {
    private static BurpExtender instance;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JTabbedPane tabbedPane;

    // 主动扫描组件
    private JTextField targetField;
    private JButton importButton;
    private JButton startActiveScanButton;
    private JButton stopActiveScanButton;
    private JTextField threadsField;
    private JTextArea logArea;
    private JButton clearLogButton;
    private JProgressBar activeProgressBar;
    private JLabel activeProgressLabel;
    private JProgressBar passiveProgressBar;
    private JLabel passiveProgressLabel;

    // 端口设置组件
    private JComboBox<String> portsCombo;
    private JTextField customPortsField;

    // 结果表格
    private JTable resultTable;
    private DefaultTableModel tableModel;
    private JScrollPane tableScrollPane;
    private JButton clearResultsButton;

    // 过滤组件
    private JComboBox<String> scanTypeFilter;
    private JTextField hostFilter;
    private JButton filterButton;
    private JButton resetFilterButton;

    // 被动扫描设置组件
    private JCheckBox enablePassiveScanCheckbox;
    private JCheckBox autoScanNewHostsCheckbox;

    // Wappalyzer 设置
    private JCheckBox enableWappalyzerCheckbox;
    private JTextField pythonPathField;
    private JButton browsePythonButton;

    // 扫描状态
    private volatile boolean activeScanRunning = false;
    private volatile boolean passiveScanRunning = false;
    private volatile boolean activeScanPaused = false;
    private volatile boolean passiveScanPaused = false;

    // 主动扫描组件
    private ExecutorService activeExecutor;
    private List<Future<?>> activeFutures;
    private AtomicInteger activeCompletedTasks;
    private int activeTotalTasks;
    private BlockingQueue<ScanTask> activeTaskQueue;

    // 被动扫描组件
    private ExecutorService passiveExecutor;
    private List<Future<?>> passiveFutures;
    private AtomicInteger passiveCompletedTasks;
    private int passiveTotalTasks;
    private BlockingQueue<ScanTask> passiveTaskQueue;

    // 共享组件
    private List<ScanResult> scanResults;
    private AtomicInteger successfulScans;
    private Set<String> scannedHosts;

    // 控制按钮
    private JButton pauseActiveScanButton;
    private JButton resumeActiveScanButton;
    private JButton stopActiveScanButton2;
    private JButton pausePassiveScanButton;
    private JButton resumePassiveScanButton;
    private JButton stopPassiveScanButton;

    // Top 1000 端口
    private final int[] TOP_1000_PORTS = {
            1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
    };

    // 常见Web端口
    private final int[] COMMON_WEB_PORTS = {
            80, 81, 82, 83, 85, 88, 443, 888, 3443, 4430, 4433, 4443, 5443,
            7001, 8000, 8001, 8002, 8003, 8008, 8009, 8010, 8080, 8081, 8082,
            8086, 8088, 8089, 8090, 8443, 8888, 9000, 9043, 9100, 9200, 9443, 9999, 10443
    };

    // 已知协议端口映射
    private final java.util.Map<Integer, String> KNOWN_PROTOCOLS = new java.util.HashMap<Integer, String>() {{
        put(21, "ftp");
        put(22, "ssh");
        put(23, "telnet");
        put(25, "smtp");
        put(53, "dns");
        put(110, "pop3");
        put(143, "imap");
        put(443, "https");
        put(993, "imaps");
        put(995, "pop3s");
        put(3306, "mysql");
        put(3389, "rdp");
        put(5432, "postgresql");
        put(5900, "vnc");
        put(6379, "redis");
        put(27017, "mongodb");
    }};

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.scanResults = new CopyOnWriteArrayList<>();
        this.successfulScans = new AtomicInteger(0);
        this.scannedHosts = new HashSet<>();

        // 初始化主动扫描组件
        this.activeFutures = new ArrayList<>();
        this.activeCompletedTasks = new AtomicInteger(0);
        this.activeTaskQueue = new LinkedBlockingQueue<>();

        // 初始化被动扫描组件
        this.passiveFutures = new ArrayList<>();
        this.passiveCompletedTasks = new AtomicInteger(0);
        this.passiveTaskQueue = new LinkedBlockingQueue<>();

        instance = this;
        callbacks.setExtensionName("Advanced Port Scanner with Wappalyzer");

        SwingUtilities.invokeLater(() -> {
            initializeUI();
            callbacks.addSuiteTab(BurpExtender.this);
            callbacks.registerHttpListener(BurpExtender.this);
            callbacks.registerExtensionStateListener(BurpExtender.this);

            callbacks.printOutput("Advanced Port Scanner with Wappalyzer loaded successfully!");
        });
    }

    public static BurpExtender getInstance() {
        return instance;
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        tabbedPane = new JTabbedPane();

        // 主动扫描面板
        JPanel activeScanPanel = createActiveScanPanel();
        tabbedPane.addTab("Active Scan", activeScanPanel);

        // 结果面板
        JPanel resultPanel = createResultPanel();
        tabbedPane.addTab("Results", resultPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createActiveScanPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 创建配置面板
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(BorderFactory.createTitledBorder("Scan Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 5, 4, 5);

        // 目标输入
        gbc.gridx = 0; gbc.gridy = 0;
        configPanel.add(new JLabel("Target IPs:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        targetField = new JTextField();
        targetField.setToolTipText("Enter IP addresses, separated by commas");
        configPanel.add(targetField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        importButton = new JButton("Import");
        importButton.addActionListener(e -> importTargetsFromFile());
        configPanel.add(importButton, gbc);

        // 线程设置
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Threads:"), gbc);

        gbc.gridx = 1; gbc.gridy = 1;
        threadsField = new JTextField("50");
        threadsField.setToolTipText("Number of concurrent threads");
        configPanel.add(threadsField, gbc);

        // 端口设置区域
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
        JPanel portPanel = createPortSettingsPanel();
        configPanel.add(portPanel, gbc);

        // Wappalyzer 设置区域
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        JPanel wappalyzerPanel = createWappalyzerPanel();
        configPanel.add(wappalyzerPanel, gbc);

        // 被动扫描设置区域
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        JPanel passiveSettingsPanel = createPassiveSettingsPanel();
        configPanel.add(passiveSettingsPanel, gbc);

        // 按钮区域
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 3;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));

        startActiveScanButton = new JButton("Start Active Scan");
        startActiveScanButton.addActionListener(e -> startActiveScan());
        buttonPanel.add(startActiveScanButton);

        stopActiveScanButton = new JButton("Stop All Scans");
        stopActiveScanButton.addActionListener(e -> stopAllScans());
        stopActiveScanButton.setEnabled(false);
        buttonPanel.add(stopActiveScanButton);

        configPanel.add(buttonPanel, gbc);

        panel.add(configPanel, BorderLayout.NORTH);

        // 进度条和控制区域
        JPanel progressControlPanel = new JPanel(new BorderLayout());
        progressControlPanel.setBorder(BorderFactory.createTitledBorder("Scan Control"));

        // 进度条区域
        JPanel progressPanel = new JPanel(new GridLayout(2, 1, 2, 2));
        progressPanel.setPreferredSize(new Dimension(1, 50));

        // 主动扫描进度和控制
        JPanel activeProgressPanel = new JPanel(new BorderLayout(5, 2));
        activeProgressPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));

        JLabel activeTitle = new JLabel("Active:");
        activeTitle.setPreferredSize(new Dimension(40, 16));
        activeProgressPanel.add(activeTitle, BorderLayout.WEST);

        activeProgressBar = new JProgressBar(0, 100);
        activeProgressBar.setStringPainted(true);
        activeProgressBar.setValue(0);
        activeProgressBar.setPreferredSize(new Dimension(100, 16));
        activeProgressPanel.add(activeProgressBar, BorderLayout.CENTER);

        activeProgressLabel = new JLabel("Ready");
        activeProgressLabel.setPreferredSize(new Dimension(80, 16));
        activeProgressPanel.add(activeProgressLabel, BorderLayout.EAST);

        // 主动扫描控制按钮
        JPanel activeControlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 2));
        pauseActiveScanButton = new JButton("Pause");
        pauseActiveScanButton.addActionListener(e -> pauseActiveScan());
        pauseActiveScanButton.setEnabled(false);
        activeControlPanel.add(pauseActiveScanButton);

        resumeActiveScanButton = new JButton("Resume");
        resumeActiveScanButton.addActionListener(e -> resumeActiveScan());
        resumeActiveScanButton.setEnabled(false);
        activeControlPanel.add(resumeActiveScanButton);

        stopActiveScanButton2 = new JButton("Stop");
        stopActiveScanButton2.addActionListener(e -> stopActiveScan());
        stopActiveScanButton2.setEnabled(false);
        activeControlPanel.add(stopActiveScanButton2);

        // 被动扫描进度和控制
        JPanel passiveProgressPanel = new JPanel(new BorderLayout(5, 2));
        passiveProgressPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));

        JLabel passiveTitle = new JLabel("Passive:");
        passiveTitle.setPreferredSize(new Dimension(40, 16));
        passiveProgressPanel.add(passiveTitle, BorderLayout.WEST);

        passiveProgressBar = new JProgressBar(0, 100);
        passiveProgressBar.setStringPainted(true);
        passiveProgressBar.setValue(0);
        passiveProgressBar.setPreferredSize(new Dimension(100, 16));
        passiveProgressPanel.add(passiveProgressBar, BorderLayout.CENTER);

        passiveProgressLabel = new JLabel("Ready");
        passiveProgressLabel.setPreferredSize(new Dimension(80, 16));
        passiveProgressPanel.add(passiveProgressLabel, BorderLayout.EAST);

        // 被动扫描控制按钮
        JPanel passiveControlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 2));
        pausePassiveScanButton = new JButton("Pause");
        pausePassiveScanButton.addActionListener(e -> pausePassiveScan());
        pausePassiveScanButton.setEnabled(false);
        passiveControlPanel.add(pausePassiveScanButton);

        resumePassiveScanButton = new JButton("Resume");
        resumePassiveScanButton.addActionListener(e -> resumePassiveScan());
        resumePassiveScanButton.setEnabled(false);
        passiveControlPanel.add(resumePassiveScanButton);

        stopPassiveScanButton = new JButton("Stop");
        stopPassiveScanButton.addActionListener(e -> stopPassiveScan());
        stopPassiveScanButton.setEnabled(false);
        passiveControlPanel.add(stopPassiveScanButton);

        progressPanel.add(activeProgressPanel);
        progressPanel.add(passiveProgressPanel);

        // 将进度和控制面板组合
        JPanel combinedPanel = new JPanel(new BorderLayout());
        combinedPanel.add(progressPanel, BorderLayout.CENTER);

        JPanel controlButtonsPanel = new JPanel(new GridLayout(2, 1, 2, 2));
        controlButtonsPanel.add(activeControlPanel);
        controlButtonsPanel.add(passiveControlPanel);
        combinedPanel.add(controlButtonsPanel, BorderLayout.SOUTH);

        progressControlPanel.add(combinedPanel, BorderLayout.CENTER);
        panel.add(progressControlPanel, BorderLayout.CENTER);

        // 日志区域
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Scan Log"));

        JPanel logToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(e -> clearLog());
        logToolbar.add(clearLogButton);

        logPanel.add(logToolbar, BorderLayout.NORTH);

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setPreferredSize(new Dimension(1, 300));
        logPanel.add(logScrollPane, BorderLayout.CENTER);

        panel.add(logPanel, BorderLayout.SOUTH);

        return panel;
    }

    // 创建 Wappalyzer 设置面板
    private JPanel createWappalyzerPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Wappalyzer Technology Detection"));
        panel.setBackground(new Color(245, 245, 245));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 8, 6, 8);
        gbc.weightx = 1.0;

        // 启用 Wappalyzer
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3;
        enableWappalyzerCheckbox = new JCheckBox("Enable Wappalyzer Technology Detection", true);
        enableWappalyzerCheckbox.setToolTipText("Use python-Wappalyzer to detect web technologies");
        enableWappalyzerCheckbox.setBackground(panel.getBackground());
        panel.add(enableWappalyzerCheckbox, gbc);

        // Python 路径标签（放在输入框上方）
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 3;
        JLabel pythonPathLabel = new JLabel("Python Path:");
        pythonPathLabel.setToolTipText("Path to Python executable");
        panel.add(pythonPathLabel, gbc);

        // Python 路径输入框
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2;
        pythonPathField = new JTextField("/usr/bin/python3");
        pythonPathField.setToolTipText("Path to Python executable");
        panel.add(pythonPathField, gbc);

        gbc.gridx = 2; gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 0;
        browsePythonButton = new JButton("Browse");
        browsePythonButton.addActionListener(e -> browsePythonPath());
        panel.add(browsePythonButton, gbc);

        return panel;
    }

    // 创建被动扫描设置面板
    private JPanel createPassiveSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Passive Scan Settings"));
        panel.setBackground(new Color(245, 245, 245));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(6, 8, 6, 8);
        gbc.weightx = 1.0;

        // 启用被动扫描
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        enablePassiveScanCheckbox = new JCheckBox("Enable Passive Scanning", true);
        enablePassiveScanCheckbox.setToolTipText("Automatically scan hosts from BurpSuite traffic");
        enablePassiveScanCheckbox.setBackground(panel.getBackground());
        panel.add(enablePassiveScanCheckbox, gbc);

        // 自动扫描新主机
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        autoScanNewHostsCheckbox = new JCheckBox("Auto-scan new hosts", true);
        autoScanNewHostsCheckbox.setToolTipText("Automatically start scanning when new hosts are detected");
        autoScanNewHostsCheckbox.setBackground(panel.getBackground());
        panel.add(autoScanNewHostsCheckbox, gbc);

        return panel;
    }

    // 创建端口设置面板
    private JPanel createPortSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Port Settings"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(3, 5, 3, 5);

        // 端口范围选择
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Port Range:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        String[] portOptions = {
                "Common Web Ports (" + COMMON_WEB_PORTS.length + " ports)",
                "Top 1000 Ports (" + TOP_1000_PORTS.length + " ports)",
                "Custom Ports"
        };
        portsCombo = new JComboBox<>(portOptions);
        portsCombo.setToolTipText("Select port range for scanning");
        portsCombo.addActionListener(e -> updatePortsFieldState());
        panel.add(portsCombo, gbc);

        // 自定义端口输入
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2;
        customPortsField = new JTextField();
        customPortsField.setToolTipText("Enter custom ports for scanning (comma separated or ranges)");
        customPortsField.setVisible(false);
        panel.add(customPortsField, gbc);

        return panel;
    }

    private void updatePortsFieldState() {
        String selected = (String) portsCombo.getSelectedItem();
        customPortsField.setVisible("Custom Ports".equals(selected));

        // 设置默认端口值
        if ("Custom Ports".equals(selected)) {
            customPortsField.setText("");
        } else if (selected != null && selected.startsWith("Common Web Ports")) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < COMMON_WEB_PORTS.length; i++) {
                if (i > 0) sb.append(",");
                sb.append(COMMON_WEB_PORTS[i]);
            }
            customPortsField.setText(sb.toString());
        } else if (selected != null && selected.startsWith("Top 1000 Ports")) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < TOP_1000_PORTS.length; i++) {
                if (i > 0) sb.append(",");
                sb.append(TOP_1000_PORTS[i]);
            }
            customPortsField.setText(sb.toString());
        }
    }

    // 浏览 Python 路径
    private void browsePythonPath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fileChooser.setDialogTitle("Select Python Executable");

        // 设置常见的 Python 可执行文件名称
        fileChooser.setAcceptAllFileFilterUsed(true);

        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            pythonPathField.setText(selectedFile.getAbsolutePath());
            log("Python path set to: " + selectedFile.getAbsolutePath());
        }
    }

    // 启动主动扫描
    private void startActiveScan() {
        String targetsText = targetField.getText().trim();
        if (targetsText.isEmpty()) {
            log("Please enter targets to scan");
            return;
        }

        try {
            int threadCount = Integer.parseInt(threadsField.getText().trim());
            if (threadCount <= 0) {
                log("Thread count must be positive");
                return;
            }

            List<Integer> portsToScan = getPortsToScan();
            if (portsToScan.isEmpty()) {
                log("No ports specified");
                return;
            }

            String[] targets = targetsText.split(",");
            startActiveTargetScan(targets, portsToScan);

        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
    }

    // 启动主动目标扫描
    private void startActiveTargetScan(String[] targets, List<Integer> portsToScan) {
        // 计算任务数量 - 每个端口都扫描 HTTP 和 HTTPS
        int taskCount = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (int port : portsToScan) {
                // 每个端口都扫描 HTTP 和 HTTPS
                String httpKey = cleanTarget + ":" + port + ":http:Active";
                String httpsKey = cleanTarget + ":" + port + ":https:Active";
                if (!scannedHosts.contains(httpKey)) taskCount++;
                if (!scannedHosts.contains(httpsKey)) taskCount++;
            }
        }

        if (taskCount == 0) {
            log("No new tasks to scan for Active scan");
            return;
        }

        // 设置主动扫描任务数量
        activeTotalTasks = taskCount;
        activeCompletedTasks.set(0);
        activeScanPaused = false;

        // 初始化主动扫描执行器
        if (activeExecutor == null || activeExecutor.isShutdown()) {
            int threadCount = Integer.parseInt(threadsField.getText().trim());
            activeExecutor = Executors.newFixedThreadPool(threadCount);
            activeFutures.clear();
            log("Initialized active executor with " + threadCount + " threads");
        }

        // 添加任务到主动队列 - 每个端口都添加 HTTP 和 HTTPS 任务
        int addedTasks = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (int port : portsToScan) {
                // 添加 HTTP 任务
                String httpKey = cleanTarget + ":" + port + ":http:Active";
                if (!scannedHosts.contains(httpKey)) {
                    ScanTask httpTask = new ScanTask(cleanTarget, port, "http", "Active");
                    activeTaskQueue.offer(httpTask);
                    addedTasks++;
                }

                // 添加 HTTPS 任务
                String httpsKey = cleanTarget + ":" + port + ":https:Active";
                if (!scannedHosts.contains(httpsKey)) {
                    ScanTask httpsTask = new ScanTask(cleanTarget, port, "https", "Active");
                    activeTaskQueue.offer(httpsTask);
                    addedTasks++;
                }
            }
        }

        log("=== Active Scan Started ===");
        log("Targets: " + targets.length + ", Ports: " + portsToScan.size() + ", Tasks: " + addedTasks);
        if (enableWappalyzerCheckbox.isSelected()) {
            log("Wappalyzer technology detection: ENABLED");
        }

        // 启动主动扫描工作线程
        activeScanRunning = true;
        startActiveScanButton.setEnabled(false);

        int threadCount = Integer.parseInt(threadsField.getText().trim());
        for (int i = 0; i < threadCount; i++) {
            Future<?> future = activeExecutor.submit(new ActiveScanWorker());
            activeFutures.add(future);
        }

        // 更新控制按钮
        updateControlButtons();

        // 更新进度显示
        SwingUtilities.invokeLater(() -> {
            activeProgressBar.setValue(0);
            activeProgressLabel.setText("0/" + activeTotalTasks + " (0%)");
        });
    }

    // 启动被动扫描
    private void startPassiveTargetScan(String[] targets, List<Integer> portsToScan) {
        // 计算任务数量 - 每个端口都扫描 HTTP 和 HTTPS
        int taskCount = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (int port : portsToScan) {
                // 每个端口都扫描 HTTP 和 HTTPS
                String httpKey = cleanTarget + ":" + port + ":http:Passive";
                String httpsKey = cleanTarget + ":" + port + ":https:Passive";
                if (!scannedHosts.contains(httpKey)) taskCount++;
                if (!scannedHosts.contains(httpsKey)) taskCount++;
            }
        }

        if (taskCount == 0) {
            log("No new tasks to scan for Passive scan");
            return;
        }

        // 设置被动扫描任务数量
        passiveTotalTasks = taskCount;
        passiveCompletedTasks.set(0);
        passiveScanPaused = false;

        // 初始化被动扫描执行器
        if (passiveExecutor == null || passiveExecutor.isShutdown()) {
            int threadCount = Integer.parseInt(threadsField.getText().trim());
            passiveExecutor = Executors.newFixedThreadPool(threadCount);
            passiveFutures.clear();
            log("Initialized passive executor with " + threadCount + " threads");
        }

        // 添加任务到被动队列 - 每个端口都添加 HTTP 和 HTTPS 任务
        int addedTasks = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (int port : portsToScan) {
                // 添加 HTTP 任务
                String httpKey = cleanTarget + ":" + port + ":http:Passive";
                if (!scannedHosts.contains(httpKey)) {
                    ScanTask httpTask = new ScanTask(cleanTarget, port, "http", "Passive");
                    passiveTaskQueue.offer(httpTask);
                    addedTasks++;
                }

                // 添加 HTTPS 任务
                String httpsKey = cleanTarget + ":" + port + ":https:Passive";
                if (!scannedHosts.contains(httpsKey)) {
                    ScanTask httpsTask = new ScanTask(cleanTarget, port, "https", "Passive");
                    passiveTaskQueue.offer(httpsTask);
                    addedTasks++;
                }
            }
        }

        log("=== Passive Scan Started ===");
        log("Targets: " + targets.length + ", Ports: " + portsToScan.size() + ", Tasks: " + addedTasks);

        // 启动被动扫描工作线程
        passiveScanRunning = true;

        int threadCount = Integer.parseInt(threadsField.getText().trim());
        for (int i = 0; i < threadCount; i++) {
            Future<?> future = passiveExecutor.submit(new PassiveScanWorker());
            passiveFutures.add(future);
        }

        // 更新控制按钮
        updateControlButtons();

        // 更新进度显示
        SwingUtilities.invokeLater(() -> {
            passiveProgressBar.setValue(0);
            passiveProgressLabel.setText("0/" + passiveTotalTasks + " (0%)");
        });
    }

    // 获取要扫描的端口
    private List<Integer> getPortsToScan() {
        List<Integer> ports = new ArrayList<>();
        String selected = (String) portsCombo.getSelectedItem();

        if ("Custom Ports".equals(selected)) {
            String portsText = customPortsField.getText().trim();
            if (!portsText.isEmpty()) {
                ports = parsePorts(portsText);
                log("Using " + ports.size() + " custom ports");
            }
        } else if (selected != null && selected.startsWith("Common Web Ports")) {
            for (int port : COMMON_WEB_PORTS) {
                ports.add(port);
            }
            log("Using " + COMMON_WEB_PORTS.length + " common web ports");
        } else if (selected != null && selected.startsWith("Top 1000 Ports")) {
            for (int port : TOP_1000_PORTS) {
                ports.add(port);
            }
            log("Using " + TOP_1000_PORTS.length + " top ports");
        }

        return ports;
    }

    private List<Integer> parsePorts(String portsText) {
        List<Integer> ports = new ArrayList<>();
        String[] parts = portsText.split(",");

        for (String part : parts) {
            part = part.trim();
            if (part.contains("-")) {
                String[] range = part.split("-");
                if (range.length == 2) {
                    try {
                        int start = Integer.parseInt(range[0].trim());
                        int end = Integer.parseInt(range[1].trim());
                        for (int port = start; port <= end; port++) {
                            if (port >= 1 && port <= 65535) {
                                ports.add(port);
                            }
                        }
                    } catch (Exception e) {
                        // 忽略错误
                    }
                }
            } else {
                try {
                    int port = Integer.parseInt(part);
                    if (port >= 1 && port <= 65535) {
                        ports.add(port);
                    }
                } catch (Exception e) {
                    // 忽略错误
                }
            }
        }

        return ports;
    }

    // 使用 Wappalyzer 检测技术栈和标题
    private WebAnalysisResult analyzeWithWappalyzer(String target, int port, String protocol) {
        if (!enableWappalyzerCheckbox.isSelected()) {
            return null;
        }

        try {
            String url = protocol + "://" + target + ":" + port;
            log("[WAPPALYZER] Analyzing: " + url);

            // 创建 Python 脚本
            File pythonScript = createComprehensiveWappalyzerScript();
            if (pythonScript == null) {
                log("[WAPPALYZER] Error: Failed to create Python script");
                return null;
            }

            // 获取 Python 路径，如果为空则使用默认的 "python"
            String pythonExecutable = pythonPathField.getText().trim();
            if (pythonExecutable.isEmpty()) {
                pythonExecutable = "python";
            }

            // 执行 Python 脚本
            ProcessBuilder pb = new ProcessBuilder(pythonExecutable, pythonScript.getAbsolutePath(), url);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // 读取输出 - 使用 UTF-8 编码
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), "UTF-8"));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line);
            }

            // 等待进程完成（超时10秒）
            boolean finished = process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                log("[WAPPALYZER] Timeout: Analysis took too long for " + url);
                return null;
            }

            // 解析输出
            if (output.length() > 0) {
                WebAnalysisResult result = parseComprehensiveWappalyzerOutput(output.toString());
                if (result != null) {
                    log("[WAPPALYZER] Analysis successful for " + url);
                    log("[WAPPALYZER] Title: " + result.title);
                    log("[WAPPALYZER] Technologies: " + result.technologies);
                    return result;
                } else {
                    log("[WAPPALYZER] No technologies detected for " + url);
                }
            } else {
                log("[WAPPALYZER] No output received for " + url);
            }

        } catch (Exception e) {
            log("[WAPPALYZER] Error analyzing " + target + ":" + port + " - " + e.getMessage());
        }

        return null;
    }

    // 创建综合的 Wappalyzer Python 脚本（包含标题提取）- 修复编码问题
    private File createComprehensiveWappalyzerScript() {
        try {
            File scriptFile = File.createTempFile("comprehensive_wappalyzer", ".py");
            scriptFile.deleteOnExit();

            // 使用 OutputStreamWriter 指定 UTF-8 编码
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(new java.io.FileOutputStream(scriptFile), "UTF-8"));
            writer.println("import json");
            writer.println("import sys");
            writer.println("import requests");
            writer.println("import re");
            writer.println("import warnings");
            writer.println("warnings.filterwarnings(\"ignore\")");
            writer.println("");
            writer.println("def comprehensive_analysis(url):");
            writer.println("    try:");
            writer.println("        session = requests.Session()");
            writer.println("        session.verify = False");
            writer.println("");
            writer.println("        headers = {");
            writer.println("            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',");
            writer.println("            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',");
            writer.println("        }");
            writer.println("");
            writer.println("        response = session.get(url, headers=headers, timeout=10)");
            writer.println("");
            writer.println("        if response.status_code == 200:");
            writer.println("            # 提取标题");
            writer.println("            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE)");
            writer.println("            title = title_match.group(1).strip() if title_match else \"未找到标题\"");
            writer.println("");
            writer.println("            # Wappalyzer分析");
            writer.println("            try:");
            writer.println("                from Wappalyzer import Wappalyzer, WebPage");
            writer.println("                wappalyzer = Wappalyzer.latest()");
            writer.println("                webpage = WebPage(");
            writer.println("                    url=url,");
            writer.println("                    html=response.text,");
            writer.println("                    headers=dict(response.headers)");
            writer.println("                )");
            writer.println("                wappalyzer_result = wappalyzer.analyze_with_versions_and_categories(webpage)");
            writer.println("                ");
            writer.println("                # 提取技术栈");
            writer.println("                technologies = extract_technologies(wappalyzer_result, response.headers, response.text)");
            writer.println("                ");
            writer.println("                return {");
            writer.println("                    'status': 'success',");
            writer.println("                    'url': url,");
            writer.println("                    'title': title,");
            writer.println("                    'technologies': technologies");
            writer.println("                }");
            writer.println("            except ImportError:");
            writer.println("                # 如果 Wappalyzer 不可用，使用基本分析");
            writer.println("                technologies = basic_analysis(response.headers, response.text)");
            writer.println("                return {");
            writer.println("                    'status': 'success',");
            writer.println("                    'url': url,");
            writer.println("                    'title': title,");
            writer.println("                    'technologies': technologies");
            writer.println("                }");
            writer.println("        else:");
            writer.println("            return {");
            writer.println("                'status': 'error',");
            writer.println("                'error': f\"HTTP {response.status_code}: {response.reason}\"");
            writer.println("            }");
            writer.println("");
            writer.println("    except Exception as e:");
            writer.println("        return {");
            writer.println("            'status': 'error',");
            writer.println("            'error': f\"请求失败: {e}\"");
            writer.println("        }");
            writer.println("");
            writer.println("def extract_technologies(wappalyzer_result, headers, html):");
            writer.println("    \"\"\"提取技术名称和版本\"\"\"");
            writer.println("    technologies = {}");
            writer.println("");
            writer.println("    # 从Wappalyzer提取");
            writer.println("    for tech_name, tech_info in wappalyzer_result.items():");
            writer.println("        versions = tech_info.get('versions', [])");
            writer.println("        version = versions[0] if versions else \"\"");
            writer.println("        technologies[tech_name] = version");
            writer.println("");
            writer.println("    # 从HTTP头提取服务器信息");
            writer.println("    server_technologies = {");
            writer.println("        'Microsoft-IIS': 'IIS',");
            writer.println("        'Apache': 'Apache',");
            writer.println("        'nginx': 'Nginx',");
            writer.println("        'Tomcat': 'Tomcat',");
            writer.println("        'Jetty': 'Jetty',");
            writer.println("        'Lighttpd': 'Lighttpd',");
            writer.println("        'OpenResty': 'OpenResty',");
            writer.println("        'Caddy': 'Caddy',");
            writer.println("        'LiteSpeed': 'LiteSpeed',");
            writer.println("        'Gunicorn': 'Gunicorn',");
            writer.println("        'uWSGI': 'uWSGI',");
            writer.println("        'CherryPy': 'CherryPy',");
            writer.println("        'Node.js': 'Node.js',");
            writer.println("        'Express': 'Express',");
            writer.println("        'Kestrel': 'Kestrel',");
            writer.println("        'Tengine': 'Tengine'");
            writer.println("    }");
            writer.println("");
            writer.println("    if 'Server' in headers:");
            writer.println("        server_header = headers['Server']");
            writer.println("        for pattern, name in server_technologies.items():");
            writer.println("            if re.search(pattern, server_header, re.IGNORECASE):");
            writer.println("                technologies[name] = extract_version_from_text(server_header)");
            writer.println("                break");
            writer.println("");
            writer.println("    # 从X-Powered-By头提取");
            writer.println("    powered_by_technologies = {");
            writer.println("        'ASP.NET': 'ASP.NET',");
            writer.println("        'PHP': 'PHP',");
            writer.println("        'JSP': 'JSP',");
            writer.println("        'Servlet': 'Java Servlet',");
            writer.println("        'Express': 'Express',");
            writer.println("        'Node.js': 'Node.js',");
            writer.println("        'Ruby': 'Ruby',");
            writer.println("        'Python': 'Python',");
            writer.println("        'Django': 'Django',");
            writer.println("        'Flask': 'Flask',");
            writer.println("        'Laravel': 'Laravel',");
            writer.println("        'Symfony': 'Symfony',");
            writer.println("        'WordPress': 'WordPress',");
            writer.println("        'Drupal': 'Drupal',");
            writer.println("        'Joomla': 'Joomla',");
            writer.println("        'Magento': 'Magento',");
            writer.println("        'Plesk': 'Plesk',");
            writer.println("        'cPanel': 'cPanel'");
            writer.println("    }");
            writer.println("");
            writer.println("    if 'X-Powered-By' in headers:");
            writer.println("        powered_by = headers['X-Powered-By']");
            writer.println("        for pattern, name in powered_by_technologies.items():");
            writer.println("            if re.search(pattern, powered_by, re.IGNORECASE):");
            writer.println("                technologies[name] = extract_version_from_text(powered_by)");
            writer.println("                break");
            writer.println("");
            writer.println("    # 从HTML提取框架信息");
            writer.println("    framework_patterns = {");
            writer.println("        'jQuery': r'jquery[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Bootstrap': r'bootstrap[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'React': r'react[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Vue.js': r'vue[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Angular': r'angular[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'jQuery UI': r'jquery-ui[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Backbone.js': r'backbone[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Ember.js': r'ember[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Foundation': r'foundation[.-](\\d+\\.\\d+\\.\\d+)',");
            writer.println("        'Semantic UI': r'semantic[.-](\\d+\\.\\d+\\.\\d+)'");
            writer.println("    }");
            writer.println("");
            writer.println("    for framework, pattern in framework_patterns.items():");
            writer.println("        match = re.search(pattern, html, re.IGNORECASE)");
            writer.println("        if match:");
            writer.println("            technologies[framework] = match.group(1)");
            writer.println("");
            writer.println("    return technologies");
            writer.println("");
            writer.println("def basic_analysis(headers, html):");
            writer.println("    \"\"\"基本技术分析（当 Wappalyzer 不可用时使用）\"\"\"");
            writer.println("    technologies = {}");
            writer.println("");
            writer.println("    # 从 HTTP 头提取");
            writer.println("    if 'Server' in headers:");
            writer.println("        technologies['Web Server'] = headers['Server']");
            writer.println("");
            writer.println("    if 'X-Powered-By' in headers:");
            writer.println("        technologies['Powered By'] = headers['X-Powered-By']");
            writer.println("");
            writer.println("    # 从 HTML 提取标题和简单框架检测");
            writer.println("    if 'jquery' in html.lower():");
            writer.println("        technologies['jQuery'] = ''");
            writer.println("");
            writer.println("    if 'bootstrap' in html.lower():");
            writer.println("        technologies['Bootstrap'] = ''");
            writer.println("");
            writer.println("    if 'react' in html.lower():");
            writer.println("        technologies['React'] = ''");
            writer.println("");
            writer.println("    return technologies");
            writer.println("");
            writer.println("def extract_version_from_text(text):");
            writer.println("    \"\"\"从文本中提取版本号\"\"\"");
            writer.println("    version_match = re.search(r'(\\d+\\.\\d+(?:\\.\\d+)?(?:\\.\\d+)?)', str(text))");
            writer.println("    return version_match.group(1) if version_match else \"\"");
            writer.println("");
            writer.println("if __name__ == \"__main__\":");
            writer.println("    if len(sys.argv) > 1:");
            writer.println("        url = sys.argv[1]");
            writer.println("        result = comprehensive_analysis(url)");
            writer.println("        print(json.dumps(result, ensure_ascii=False))");

            writer.close();
            return scriptFile;

        } catch (Exception e) {
            log("[WAPPALYZER] Error creating Python script: " + e.getMessage());
            return null;
        }
    }

    // 解析综合 Wappalyzer 输出 - 使用简单的字符串解析代替 Gson
    private WebAnalysisResult parseComprehensiveWappalyzerOutput(String jsonOutput) {
        try {
            // 提取 JSON 部分
            String jsonStr = extractJsonFromOutput(jsonOutput);
            if (jsonStr == null) {
                log("[WAPPALYZER] Could not extract JSON from output");
                return null;
            }

            // 使用简单的字符串解析提取关键信息
            String title = extractJsonField(jsonStr, "title");
            String status = extractJsonField(jsonStr, "status");

            // 检查状态
            if (!"success".equals(status)) {
                String error = extractJsonField(jsonStr, "error");
                log("[WAPPALYZER] Analysis failed: " + error);
                return null;
            }

            // 提取技术栈信息
            String technologies = parseTechnologiesFromJson(jsonStr);

            if (title != null || technologies != null) {
                return new WebAnalysisResult(
                        title != null ? title : "未找到标题",
                        technologies != null ? technologies : "未检测到技术栈"
                );
            }

        } catch (Exception e) {
            log("[WAPPALYZER] Error parsing comprehensive output: " + e.getMessage());
        }
        return null;
    }

    // 从 JSON 字符串中提取字段值
    private String extractJsonField(String jsonStr, String fieldName) {
        try {
            Pattern pattern = Pattern.compile("\"" + fieldName + "\"\\s*:\\s*\"([^\"]*)\"");
            Matcher matcher = pattern.matcher(jsonStr);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            log("[WAPPALYZER] Error extracting field " + fieldName + ": " + e.getMessage());
        }
        return null;
    }

    // 解析技术栈信息
    private String parseTechnologiesFromJson(String jsonStr) {
        try {
            // 查找 technologies 对象
            int techStart = jsonStr.indexOf("\"technologies\"");
            if (techStart == -1) {
                return null;
            }

            // 找到 technologies 对象的开始和结束位置
            int braceStart = jsonStr.indexOf("{", techStart);
            int braceEnd = findMatchingBrace(jsonStr, braceStart);
            if (braceStart == -1 || braceEnd == -1) {
                return null;
            }

            String technologiesObj = jsonStr.substring(braceStart, braceEnd + 1);

            // 提取技术名称和版本
            List<String> techList = new ArrayList<>();
            Pattern techPattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
            Matcher techMatcher = techPattern.matcher(technologiesObj);

            while (techMatcher.find()) {
                String techName = techMatcher.group(1);
                String version = techMatcher.group(2);
                if (!version.isEmpty()) {
                    techList.add(techName + " " + version);
                } else {
                    techList.add(techName);
                }
            }

            if (!techList.isEmpty()) {
                return String.join(", ", techList);
            }

        } catch (Exception e) {
            log("[WAPPALYZER] Error parsing technologies: " + e.getMessage());
        }
        return null;
    }

    // 找到匹配的大括号
    private int findMatchingBrace(String str, int startIndex) {
        int count = 1;
        for (int i = startIndex + 1; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '{') {
                count++;
            } else if (c == '}') {
                count--;
                if (count == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    // 从输出中提取 JSON 部分
    private String extractJsonFromOutput(String output) {
        try {
            int jsonStart = output.indexOf("{");
            int jsonEnd = output.lastIndexOf("}");

            if (jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart) {
                return output.substring(jsonStart, jsonEnd + 1);
            }
        } catch (Exception e) {
            log("[WAPPALYZER] Error extracting JSON: " + e.getMessage());
        }
        return null;
    }

    // 获取端口的实际协议（用于显示）
    private String getActualProtocol(int port, String requestedProtocol) {
        if (KNOWN_PROTOCOLS.containsKey(port)) {
            return KNOWN_PROTOCOLS.get(port);
        }
        return requestedProtocol;
    }

    private ScanResult scanHttpTarget(String target, int port, String protocol, String scanType) {
        try {
            String urlStr = protocol + "://" + target + ":" + port;
            URL url = new URL(urlStr);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            connection.setRequestProperty("User-Agent", "Mozilla/5.0");

            int responseCode = connection.getResponseCode();
            String serverHeader = connection.getHeaderField("Server");

            StringBuilder banner = new StringBuilder();
            String title = "";

            // 对所有 HTTP/HTTPS 服务使用 Wappalyzer 检测技术栈和标题
            if (enableWappalyzerCheckbox.isSelected() && (responseCode == 200 || responseCode == 301 || responseCode == 302 || responseCode == 403 || responseCode == 401)) {
                WebAnalysisResult analysisResult = analyzeWithWappalyzer(target, port, protocol);
                if (analysisResult != null) {
                    // 使用技术栈信息和标题
                    if (!analysisResult.technologies.isEmpty()) {
                        banner.append("Tech: ").append(analysisResult.technologies);
                    }
                    title = analysisResult.title;
                    log("[SCAN] Using technology info: " + analysisResult.technologies);
                    log("[SCAN] Title: " + title);
                } else {
                    // 如果没有检测到技术栈，回退到显示 Server 信息
                    if (serverHeader != null) {
                        banner.append("Server: ").append(serverHeader);
                    } else {
                        banner.append("Web Service");
                    }
                    log("[SCAN] No technology info detected, using server info");
                }
            } else {
                // 如果 Wappalyzer 未启用或状态码不支持，显示 Server 信息
                if (serverHeader != null) {
                    banner.append("Server: ").append(serverHeader);
                } else {
                    banner.append("Web Service");
                }
            }

            connection.disconnect();

            // 获取实际协议用于显示
            String actualProtocol = getActualProtocol(port, protocol);

            ScanResult result = new ScanResult(
                    target, port, actualProtocol,
                    banner.toString(),
                    title,
                    responseCode, scanType
            );

            log("[SCAN] Final banner: " + banner.toString());
            return result;

        } catch (Exception e) {
            log("[SCAN] Error scanning " + target + ":" + port + " - " + e.getMessage());
            return null;
        }
    }

    private ScanResult scanProtocolTarget(String target, int port, String protocol, String scanType) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(target, port), 1000);
            socket.setSoTimeout(1000);

            // 获取实际协议
            String actualProtocol = getActualProtocol(port, protocol);

            String banner = actualProtocol.toUpperCase() + " Service";

            return new ScanResult(
                    target, port, actualProtocol,
                    banner,
                    "",
                    200, scanType
            );

        } catch (Exception e) {
            return null;
        }
    }

    // 主动扫描工作线程
    private class ActiveScanWorker implements Runnable {
        @Override
        public void run() {
            while (activeScanRunning && !Thread.currentThread().isInterrupted()) {
                try {
                    if (activeScanPaused) {
                        Thread.sleep(100);
                        continue;
                    }

                    ScanTask task = activeTaskQueue.poll(50, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (task != null) {
                        scanSingleTarget(task);
                    } else {
                        if (activeCompletedTasks.get() >= activeTotalTasks) {
                            break;
                        }
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }

    // 被动扫描工作线程
    private class PassiveScanWorker implements Runnable {
        @Override
        public void run() {
            while (passiveScanRunning && !Thread.currentThread().isInterrupted()) {
                try {
                    if (passiveScanPaused) {
                        Thread.sleep(100);
                        continue;
                    }

                    ScanTask task = passiveTaskQueue.poll(50, java.util.concurrent.TimeUnit.MILLISECONDS);
                    if (task != null) {
                        scanSingleTarget(task);
                    } else {
                        if (passiveCompletedTasks.get() >= passiveTotalTasks) {
                            break;
                        }
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }

    // 扫描单个目标
    private void scanSingleTarget(ScanTask task) {
        try {
            String hostPortKey = task.target + ":" + task.port + ":" + task.protocol + ":" + task.scanType;

            if (scannedHosts.contains(hostPortKey)) {
                updateProgress(task.scanType);
                return;
            }

            ScanResult result = null;

            // 根据协议类型决定扫描方式
            if (task.protocol.equals("http") || task.protocol.equals("https")) {
                result = scanHttpTarget(task.target, task.port, task.protocol, task.scanType);
            } else {
                // 对于非 HTTP/HTTPS 协议，使用协议检测
                result = scanProtocolTarget(task.target, task.port, task.protocol, task.scanType);
            }

            if (result != null) {
                scannedHosts.add(hostPortKey);
                scanResults.add(result);
                addResultToTable(result);
                successfulScans.incrementAndGet();
                log("[FOUND] " + task.scanType + " - " + result.proto + "://" + task.target + ":" + task.port + " - " + result.banner);
            }

        } catch (Exception e) {
            // 静默处理连接错误
        }

        updateProgress(task.scanType);
    }

    // 更新进度
    private void updateProgress(String scanType) {
        SwingUtilities.invokeLater(() -> {
            if ("Active".equals(scanType)) {
                int completed = activeCompletedTasks.incrementAndGet();
                int progress = activeTotalTasks > 0 ? (completed * 100) / activeTotalTasks : 0;
                activeProgressBar.setValue(progress);
                activeProgressLabel.setText(completed + "/" + activeTotalTasks + " (" + progress + "%)");

                if (completed >= activeTotalTasks) {
                    activeProgressLabel.setText("Active completed");
                    log("=== Active Scan Complete ===");
                    activeScanRunning = false;
                    startActiveScanButton.setEnabled(true);
                    updateControlButtons();
                }
            } else {
                int completed = passiveCompletedTasks.incrementAndGet();
                int progress = passiveTotalTasks > 0 ? (completed * 100) / passiveTotalTasks : 0;
                passiveProgressBar.setValue(progress);
                passiveProgressLabel.setText(completed + "/" + passiveTotalTasks + " (" + progress + "%)");

                if (completed >= passiveTotalTasks) {
                    passiveProgressLabel.setText("Passive completed");
                    log("=== Passive Scan Complete ===");
                    passiveScanRunning = false;
                    updateControlButtons();
                }
            }
        });
    }

    // 暂停主动扫描
    private void pauseActiveScan() {
        activeScanPaused = true;
        pauseActiveScanButton.setEnabled(false);
        resumeActiveScanButton.setEnabled(true);
        log("Active scan paused");
    }

    // 继续主动扫描
    private void resumeActiveScan() {
        activeScanPaused = false;
        pauseActiveScanButton.setEnabled(true);
        resumeActiveScanButton.setEnabled(false);
        log("Active scan resumed");
    }

    // 停止主动扫描
    private void stopActiveScan() {
        activeScanRunning = false;
        activeScanPaused = false;
        activeTaskQueue.clear();
        activeTotalTasks = activeCompletedTasks.get();
        activeProgressLabel.setText("Stopped");
        startActiveScanButton.setEnabled(true);
        log("Active scan stopped");
        updateControlButtons();

        if (activeExecutor != null) {
            activeExecutor.shutdownNow();
            activeExecutor = null;
        }
        activeFutures.clear();
    }

    // 暂停被动扫描
    private void pausePassiveScan() {
        passiveScanPaused = true;
        pausePassiveScanButton.setEnabled(false);
        resumePassiveScanButton.setEnabled(true);
        log("Passive scan paused");
    }

    // 继续被动扫描
    private void resumePassiveScan() {
        passiveScanPaused = false;
        pausePassiveScanButton.setEnabled(true);
        resumePassiveScanButton.setEnabled(false);
        log("Passive scan resumed");
    }

    // 停止被动扫描
    private void stopPassiveScan() {
        passiveScanRunning = false;
        passiveScanPaused = false;
        passiveTaskQueue.clear();
        passiveTotalTasks = passiveCompletedTasks.get();
        passiveProgressLabel.setText("Stopped");
        log("Passive scan stopped");
        updateControlButtons();

        if (passiveExecutor != null) {
            passiveExecutor.shutdownNow();
            passiveExecutor = null;
        }
        passiveFutures.clear();
    }

    // 停止所有扫描
    private void stopAllScans() {
        stopActiveScan();
        stopPassiveScan();
    }

    // 更新控制按钮状态
    private void updateControlButtons() {
        pauseActiveScanButton.setEnabled(activeScanRunning && !activeScanPaused);
        resumeActiveScanButton.setEnabled(activeScanRunning && activeScanPaused);
        stopActiveScanButton2.setEnabled(activeScanRunning);

        pausePassiveScanButton.setEnabled(passiveScanRunning && !passiveScanPaused);
        resumePassiveScanButton.setEnabled(passiveScanRunning && passiveScanPaused);
        stopPassiveScanButton.setEnabled(passiveScanRunning);

        stopActiveScanButton.setEnabled(activeScanRunning || passiveScanRunning);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest && enablePassiveScanCheckbox.isSelected()) {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                String host = requestInfo.getUrl().getHost();

                if (isValidIPAddress(host)) {
                    String hostKey = host + ":passive-check";
                    if (!scannedHosts.contains(hostKey)) {
                        scannedHosts.add(hostKey);
                        log("[PASSIVE] Detected new IP from traffic: " + host);

                        if (autoScanNewHostsCheckbox.isSelected()) {
                            SwingUtilities.invokeLater(() -> {
                                List<Integer> ports = getPortsToScan();
                                if (!ports.isEmpty()) {
                                    log("[PASSIVE] Starting auto-scan for " + host + " on " + ports.size() + " ports");
                                    startPassiveTargetScan(new String[]{host}, ports);
                                }
                            });
                        }
                    }
                }
            } catch (Exception e) {
                // 忽略解析错误
            }
        }
    }

    private boolean isValidIPAddress(String host) {
        return host.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    }

    // 结果面板创建方法 - 增加 Target 列
    private JPanel createResultPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 顶部工具栏
        JPanel toolbarPanel = new JPanel(new BorderLayout());

        // 过滤区域
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        filterPanel.setBorder(BorderFactory.createTitledBorder("Filter Results"));

        filterPanel.add(new JLabel("Scan Type:"));
        scanTypeFilter = new JComboBox<>(new String[]{"All", "Active", "Passive"});
        filterPanel.add(scanTypeFilter);

        filterPanel.add(new JLabel("Host Filter:"));
        hostFilter = new JTextField(15);
        hostFilter.setToolTipText("Filter by host name or IP address");
        filterPanel.add(hostFilter);

        filterButton = new JButton("Apply Filter");
        filterButton.addActionListener(e -> filterResults());
        filterPanel.add(filterButton);

        resetFilterButton = new JButton("Clear Filter");
        resetFilterButton.addActionListener(e -> resetFilter());
        filterPanel.add(resetFilterButton);

        // 操作按钮区域
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        actionPanel.setBorder(BorderFactory.createTitledBorder("Actions"));

        clearResultsButton = new JButton("Clear All Results");
        clearResultsButton.addActionListener(e -> clearAllResults());
        clearResultsButton.setToolTipText("Clear all scan results from the table");
        actionPanel.add(clearResultsButton);

        toolbarPanel.add(filterPanel, BorderLayout.WEST);
        toolbarPanel.add(actionPanel, BorderLayout.EAST);
        panel.add(toolbarPanel, BorderLayout.NORTH);

        // 结果表格 - 增加 Target 列
        String[] columnNames = {"Target", "Host", "Port", "Protocol", "Title", "Banner", "Status", "Scan Type"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        resultTable = new JTable(tableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 设置自定义渲染器，支持自动换行和居中显示
        MultiLineTableCellRenderer renderer = new MultiLineTableCellRenderer();
        for (int i = 0; i < resultTable.getColumnCount(); i++) {
            resultTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        // 设置行高以支持多行文本
        resultTable.setRowHeight(60);

        // 设置列宽
        TableColumnModel columnModel = resultTable.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(180); // Target
        columnModel.getColumn(1).setPreferredWidth(120); // Host
        columnModel.getColumn(2).setPreferredWidth(60);  // Port
        columnModel.getColumn(3).setPreferredWidth(70);  // Protocol
        columnModel.getColumn(4).setPreferredWidth(200); // Title
        columnModel.getColumn(5).setPreferredWidth(300); // Banner
        columnModel.getColumn(6).setPreferredWidth(80);  // Status
        columnModel.getColumn(7).setPreferredWidth(80);  // Scan Type

        // 添加右键菜单
        JPopupMenu popupMenu = createRightClickMenu();
        resultTable.setComponentPopupMenu(popupMenu);

        tableScrollPane = new JScrollPane(resultTable);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        return panel;
    }

    // 创建右键菜单
    private JPopupMenu createRightClickMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        // 复制单元格内容
        JMenuItem copyCellItem = new JMenuItem("Copy Cell");
        copyCellItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedCell();
            }
        });
        popupMenu.add(copyCellItem);

        // 复制整行
        JMenuItem copyRowItem = new JMenuItem("Copy Row");
        copyRowItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRow();
            }
        });
        popupMenu.add(copyRowItem);

        // 复制 Target URL
        JMenuItem copyTargetItem = new JMenuItem("Copy Target URL");
        copyTargetItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyTargetUrl();
            }
        });
        popupMenu.add(copyTargetItem);

        return popupMenu;
    }

    // 复制选中的单元格
    private void copySelectedCell() {
        int row = resultTable.getSelectedRow();
        int col = resultTable.getSelectedColumn();

        if (row != -1 && col != -1) {
            Object value = resultTable.getValueAt(row, col);
            if (value != null) {
                StringSelection stringSelection = new StringSelection(value.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
                log("Copied cell content: " + value.toString());
            }
        }
    }

    // 复制整行内容
    private void copySelectedRow() {
        int row = resultTable.getSelectedRow();

        if (row != -1) {
            StringBuilder rowData = new StringBuilder();
            for (int col = 0; col < resultTable.getColumnCount(); col++) {
                Object value = resultTable.getValueAt(row, col);
                if (value != null) {
                    if (col > 0) rowData.append("\t");
                    rowData.append(value.toString());
                }
            }

            StringSelection stringSelection = new StringSelection(rowData.toString());
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
            log("Copied row data");
        }
    }

    // 复制 Target URL
    private void copyTargetUrl() {
        int row = resultTable.getSelectedRow();

        if (row != -1) {
            Object targetValue = resultTable.getValueAt(row, 0); // Target 列
            if (targetValue != null) {
                StringSelection stringSelection = new StringSelection(targetValue.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
                log("Copied target URL: " + targetValue.toString());
            }
        }
    }

    // 自定义单元格渲染器，支持自动换行和居中显示
    private class MultiLineTableCellRenderer extends JTextArea implements javax.swing.table.TableCellRenderer {
        public MultiLineTableCellRenderer() {
            setLineWrap(true);
            setWrapStyleWord(true);
            setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {

            // 设置文本
            if (value != null) {
                setText(value.toString());
            } else {
                setText("");
            }

            // 设置字体
            setFont(table.getFont());

            // 设置背景和前景色
            if (isSelected) {
                setBackground(table.getSelectionBackground());
                setForeground(table.getSelectionForeground());
            } else {
                setBackground(table.getBackground());
                setForeground(table.getForeground());
            }

            // 设置边框
            setBorder(hasFocus ?
                    UIManager.getBorder("Table.focusCellHighlightBorder") :
                    BorderFactory.createEmptyBorder(1, 2, 1, 2));

            // 设置文本居中
            setAlignmentX(CENTER_ALIGNMENT);

            return this;
        }
    }

    private void clearAllResults() {
        int result = JOptionPane.showConfirmDialog(mainPanel,
                "Are you sure you want to clear all scan results?",
                "Clear Results",
                JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            scanResults.clear();
            tableModel.setRowCount(0);
            scannedHosts.clear();
            successfulScans.set(0);
            log("All scan results cleared");
        }
    }

    private void clearLog() {
        logArea.setText("");
        log("Log cleared");
    }

    private void importTargetsFromFile() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(fileChooser.getSelectedFile()));
                StringBuilder targets = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        if (targets.length() > 0) {
                            targets.append(",");
                        }
                        targets.append(line.trim());
                    }
                }
                reader.close();
                targetField.setText(targets.toString());
                log("Targets imported: " + fileChooser.getSelectedFile().getName());
            } catch (Exception e) {
                log("Error importing: " + e.getMessage());
            }
        }
    }

    private void addResultToTable(ScanResult result) {
        SwingUtilities.invokeLater(() -> {
            // 构建 Target URL
            String targetUrl = result.proto + "://" + result.host + ":" + result.port;

            tableModel.addRow(new Object[]{
                    targetUrl, // Target 列
                    result.host,
                    result.port,
                    result.proto,
                    result.title,
                    result.banner,
                    result.code == 200 ? "Open" : "Closed",
                    result.scanType
            });
        });
    }

    private void filterResults() {
        String scanType = (String) scanTypeFilter.getSelectedItem();
        String hostFilterText = hostFilter.getText().trim().toLowerCase();

        tableModel.setRowCount(0);

        for (ScanResult result : scanResults) {
            boolean matchesType = "All".equals(scanType) || result.scanType.equals(scanType);
            boolean matchesHost = hostFilterText.isEmpty() ||
                    result.host.toLowerCase().contains(hostFilterText);

            if (matchesType && matchesHost) {
                addResultToTable(result);
            }
        }
    }

    private void resetFilter() {
        scanTypeFilter.setSelectedIndex(0);
        hostFilter.setText("");
        filterResults();
    }

    @Override
    public void extensionUnloaded() {
        log("Extension unloaded");
        if (activeExecutor != null) {
            activeExecutor.shutdownNow();
        }
        if (passiveExecutor != null) {
            passiveExecutor.shutdownNow();
        }
    }

    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    @Override
    public String getTabCaption() {
        return "Port Scanner with Wappalyzer";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // 内部类
    private static class ScanTask {
        String target;
        int port;
        String protocol;
        String scanType;
        ScanTask(String target, int port, String protocol, String scanType) {
            this.target = target;
            this.port = port;
            this.protocol = protocol;
            this.scanType = scanType;
        }
    }

    private static class ScanResult {
        String host;
        int port;
        String proto;
        String banner;
        String title;
        int code;
        String scanType;

        ScanResult(String host, int port, String proto, String banner, String title, int code, String scanType) {
            this.host = host;
            this.port = port;
            this.proto = proto;
            this.banner = banner;
            this.title = title;
            this.code = code;
            this.scanType = scanType;
        }
    }

    // Web 分析结果类
    private static class WebAnalysisResult {
        String title;
        String technologies;

        WebAnalysisResult(String title, String technologies) {
            this.title = title;
            this.technologies = technologies;
        }
    }
}
