/**
 * ========================================================
 * Advanced Port Scanner for BurpSuite
 *
 * 开发者: shifeige
 * GitHub: https://github.com/shifeige
 *
 * ========================================================
 */


package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
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
import java.io.IOException;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

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

    // 指纹库配置组件
    private JTextField fingerprintFilePathField;
    private JButton browseFingerprintFileButton;
    private JButton reloadFingerprintsButton;

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

    // 指纹识别组件
    private ServiceFingerprintLibrary fingerprintLibrary;

    // Top 1000 端口
    private final int[] TOP_1000_PORTS = {
            1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
    };

    // 常见Web端口
    private final int[] COMMON_WEB_PORTS = {
            80,81,82,83,85,88,443,888,3443,4430,4433,4443,5443,7001,8000,8001,8002,8003,8008,8009,8010,8080,8081,8082,8086,8088,8089,8090,8443,8888,9000,9043,9100,9200,9443,9999,10443
    };

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // 初始化指纹库
        this.fingerprintLibrary = new ServiceFingerprintLibrary();

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
        callbacks.setExtensionName("Advanced Port Scanner");

        SwingUtilities.invokeLater(() -> {
            initializeUI();
            callbacks.addSuiteTab(BurpExtender.this);
            callbacks.registerHttpListener(BurpExtender.this);
            callbacks.registerExtensionStateListener(BurpExtender.this);

            // 自动加载指纹库
            autoLoadFingerprintLibrary();

            callbacks.printOutput("Advanced Port Scanner loaded successfully!");
        });
    }

    // 自动加载指纹库
    private void autoLoadFingerprintLibrary() {
        String defaultPath = "portscanner_fingerprints.json";
        File defaultFile = new File(defaultPath);

        if (defaultFile.exists()) {
            fingerprintFilePathField.setText(defaultPath);
            loadFingerprintLibrary();
        } else {
            // 创建默认指纹库文件
            createDefaultFingerprintFile(defaultPath);
            fingerprintFilePathField.setText(defaultPath);
            loadFingerprintLibrary();
        }
    }

    // 创建默认指纹库文件
    private void createDefaultFingerprintFile(String filePath) {
        try {
            String defaultFingerprints = generateDefaultFingerprints();
            Files.write(Paths.get(filePath), defaultFingerprints.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log("Created default fingerprint library: " + filePath);
        } catch (Exception e) {
            log("Error creating default fingerprint file: " + e.getMessage());
        }
    }

    // 加载指纹库
    private void loadFingerprintLibrary() {
        String filePath = fingerprintFilePathField.getText().trim();
        if (filePath.isEmpty()) {
            log("Please select a fingerprint file");
            return;
        }

        File file = new File(filePath);
        if (!file.exists()) {
            log("Fingerprint file does not exist: " + filePath);
            return;
        }

        try {
            fingerprintLibrary.loadFingerprintsFromFile(filePath);
            log("Fingerprint library loaded: " + fingerprintLibrary.getFingerprintCount() + " fingerprints from " + filePath);
        } catch (Exception e) {
            log("Error loading fingerprint library: " + e.getMessage());
        }
    }

    // 重新加载指纹库
    private void reloadFingerprintLibrary() {
        loadFingerprintLibrary();
    }

    // 浏览指纹文件
    private void browseFingerprintFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            fingerprintFilePathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            loadFingerprintLibrary();
        }
    }

    // 初始化UI
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

    // 创建主动扫描面板
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

        // 指纹库配置区域
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        JPanel fingerprintPanel = createFingerprintConfigPanel();
        configPanel.add(fingerprintPanel, gbc);

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

    // 创建指纹库配置面板
    private JPanel createFingerprintConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Fingerprint Library"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(3, 5, 3, 5);

        // 文件路径
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Fingerprint File:"), gbc);

        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        fingerprintFilePathField = new JTextField();
        fingerprintFilePathField.setToolTipText("Path to fingerprint JSON file");
        panel.add(fingerprintFilePathField, gbc);

        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0;
        browseFingerprintFileButton = new JButton("Browse");
        browseFingerprintFileButton.addActionListener(e -> browseFingerprintFile());
        panel.add(browseFingerprintFileButton, gbc);

        gbc.gridx = 3; gbc.gridy = 0; gbc.weightx = 0;
        reloadFingerprintsButton = new JButton("Reload");
        reloadFingerprintsButton.addActionListener(e -> reloadFingerprintLibrary());
        panel.add(reloadFingerprintsButton, gbc);

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

    // 创建结果面板
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

        // 结果表格
        String[] columnNames = {"Host", "Port", "Protocol", "Service", "Banner", "Status", "Scan Type"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        resultTable = new JTable(tableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 设置列宽
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(70);
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(200);
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        resultTable.getColumnModel().getColumn(6).setPreferredWidth(80);

        // 设置居中显示
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        resultTable.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        resultTable.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        resultTable.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);

        tableScrollPane = new JScrollPane(resultTable);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        return panel;
    }

    // 实现 ITab 接口的方法
    @Override
    public String getTabCaption() {
        return "Port Scanner";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // 实现 IExtensionStateListener 接口的方法
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

    // 实现 IHttpListener 接口的方法
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
                                List<PortProtocol> ports = getPortsToScan();
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

    // 日志方法
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void updatePortsFieldState() {
        String selected = (String) portsCombo.getSelectedItem();
        customPortsField.setVisible("Custom Ports".equals(selected));

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

            List<PortProtocol> portsToScan = getPortsToScan();
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

    // 获取要扫描的端口
    private List<PortProtocol> getPortsToScan() {
        List<PortProtocol> ports = new ArrayList<>();
        String selected = (String) portsCombo.getSelectedItem();

        if ("Custom Ports".equals(selected)) {
            String portsText = customPortsField.getText().trim();
            if (!portsText.isEmpty()) {
                List<Integer> portNumbers = parsePorts(portsText);
                for (int port : portNumbers) {
                    String protocol = getProtocolByPort(port);
                    ports.add(new PortProtocol(port, protocol));
                }
                log("Using " + ports.size() + " custom ports");
            }
        } else if (selected != null && selected.startsWith("Common Web Ports")) {
            for (int port : COMMON_WEB_PORTS) {
                String protocol = getProtocolByPort(port);
                ports.add(new PortProtocol(port, protocol));
            }
            log("Using " + COMMON_WEB_PORTS.length + " common web ports");
        } else if (selected != null && selected.startsWith("Top 1000 Ports")) {
            for (int port : TOP_1000_PORTS) {
                String protocol = getProtocolByPort(port);
                ports.add(new PortProtocol(port, protocol));
            }
            log("Using " + TOP_1000_PORTS.length + " top ports");
        }

        return ports;
    }

    // 启动主动目标扫描
    private void startActiveTargetScan(String[] targets, List<PortProtocol> portsToScan) {
        int taskCount = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (PortProtocol portProto : portsToScan) {
                String hostPortKey = cleanTarget + ":" + portProto.port + ":" + portProto.protocol + ":Active";
                if (!scannedHosts.contains(hostPortKey)) {
                    taskCount++;
                }
            }
        }

        if (taskCount == 0) {
            log("No new tasks to scan for Active scan");
            return;
        }

        activeTotalTasks = taskCount;
        activeCompletedTasks.set(0);
        activeScanPaused = false;

        if (activeExecutor == null || activeExecutor.isShutdown()) {
            int threadCount = Integer.parseInt(threadsField.getText().trim());
            activeExecutor = Executors.newFixedThreadPool(threadCount);
            activeFutures.clear();
            log("Initialized active executor with " + threadCount + " threads");
        }

        int addedTasks = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (PortProtocol portProto : portsToScan) {
                String hostPortKey = cleanTarget + ":" + portProto.port + ":" + portProto.protocol + ":Active";
                if (!scannedHosts.contains(hostPortKey)) {
                    ScanTask task = new ScanTask(cleanTarget, portProto.port, portProto.protocol, "Active");
                    activeTaskQueue.offer(task);
                    addedTasks++;
                }
            }
        }

        log("=== Active Scan Started ===");
        log("Targets: " + targets.length + ", Ports: " + portsToScan.size() + ", Tasks: " + addedTasks);

        activeScanRunning = true;
        startActiveScanButton.setEnabled(false);

        int threadCount = Integer.parseInt(threadsField.getText().trim());
        for (int i = 0; i < threadCount; i++) {
            Future<?> future = activeExecutor.submit(new ActiveScanWorker());
            activeFutures.add(future);
        }

        updateControlButtons();

        SwingUtilities.invokeLater(() -> {
            activeProgressBar.setValue(0);
            activeProgressLabel.setText("0/" + activeTotalTasks + " (0%)");
        });
    }

    // 启动被动扫描
    private void startPassiveTargetScan(String[] targets, List<PortProtocol> portsToScan) {
        int taskCount = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (PortProtocol portProto : portsToScan) {
                String hostPortKey = cleanTarget + ":" + portProto.port + ":" + portProto.protocol + ":Passive";
                if (!scannedHosts.contains(hostPortKey)) {
                    taskCount++;
                }
            }
        }

        if (taskCount == 0) {
            log("No new tasks to scan for Passive scan");
            return;
        }

        passiveTotalTasks = taskCount;
        passiveCompletedTasks.set(0);
        passiveScanPaused = false;

        if (passiveExecutor == null || passiveExecutor.isShutdown()) {
            int threadCount = Integer.parseInt(threadsField.getText().trim());
            passiveExecutor = Executors.newFixedThreadPool(threadCount);
            passiveFutures.clear();
            log("Initialized passive executor with " + threadCount + " threads");
        }

        int addedTasks = 0;
        for (String target : targets) {
            String cleanTarget = target.trim();
            for (PortProtocol portProto : portsToScan) {
                String hostPortKey = cleanTarget + ":" + portProto.port + ":" + portProto.protocol + ":Passive";
                if (!scannedHosts.contains(hostPortKey)) {
                    ScanTask task = new ScanTask(cleanTarget, portProto.port, portProto.protocol, "Passive");
                    passiveTaskQueue.offer(task);
                    addedTasks++;
                }
            }
        }

        log("=== Passive Scan Started ===");
        log("Targets: " + targets.length + ", Ports: " + portsToScan.size() + ", Tasks: " + addedTasks);

        passiveScanRunning = true;

        int threadCount = Integer.parseInt(threadsField.getText().trim());
        for (int i = 0; i < threadCount; i++) {
            Future<?> future = passiveExecutor.submit(new PassiveScanWorker());
            passiveFutures.add(future);
        }

        updateControlButtons();

        SwingUtilities.invokeLater(() -> {
            passiveProgressBar.setValue(0);
            passiveProgressLabel.setText("0/" + passiveTotalTasks + " (0%)");
        });
    }

    // 扫描HTTP/HTTPS目标（带指纹识别）
    private ScanResult scanHttpTarget(String target, int port, String protocol, String scanType) {
        try {
            // 设置SSL信任所有证书（用于处理自签名证书）
            if (protocol.equals("https")) {
                setupSSLTrust();
            }

            String urlStr = protocol + "://" + target + ":" + port;
            URL url = new URL(urlStr);
            HttpURLConnection connection;

            if (protocol.equals("https")) {
                connection = (HttpsURLConnection) url.openConnection();
            } else {
                connection = (HttpURLConnection) url.openConnection();
            }

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);  // 增加连接超时
            connection.setReadTimeout(8000);     // 增加读取超时
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; BurpPortScanner/1.0)");
            connection.setInstanceFollowRedirects(true);
            connection.setUseCaches(false);

            // 对于特定服务尝试特殊端点
            if (port == 15672 || port == 443 || port == 8443) {
                // 尝试RabbitMQ管理界面
                ScanResult rabbitResult = tryRabbitMQEndpoints(target, port, protocol, scanType);
                if (rabbitResult != null) {
                    return rabbitResult;
                }
            }

            int responseCode = connection.getResponseCode();

            // 收集响应头信息
            Map<String, String> headers = new HashMap<>();
            String serverHeader = connection.getHeaderField("Server");
            if (serverHeader != null) {
                headers.put("Server", serverHeader);
            }
            headers.put("X-Powered-By", connection.getHeaderField("X-Powered-By"));
            headers.put("Content-Type", connection.getHeaderField("Content-Type"));
            headers.put("X-Content-Type-Options", connection.getHeaderField("X-Content-Type-Options"));

            // 读取响应内容
            String responseContent = "";
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 200) {  // 增加读取行数
                    responseBuilder.append(line).append("\n");
                    lineCount++;
                }
                reader.close();
                responseContent = responseBuilder.toString();
            } catch (Exception e) {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
                    StringBuilder responseBuilder = new StringBuilder();
                    String line;
                    int lineCount = 0;
                    while ((line = reader.readLine()) != null && lineCount < 100) {
                        responseBuilder.append(line).append("\n");
                        lineCount++;
                    }
                    reader.close();
                    responseContent = responseBuilder.toString();
                } catch (Exception ex) {
                    // 忽略错误
                }
            }

            connection.disconnect();

            // 进行服务指纹识别
            ServiceFingerprint fingerprint = identifyService(target, port, protocol, responseContent, headers);

            String serviceInfo = "Unknown Service";
            String banner = "";

            // 构建banner信息
            if (fingerprint != null) {
                serviceInfo = fingerprint.getServiceName();
                StringBuilder bannerBuilder = new StringBuilder();
                bannerBuilder.append(fingerprint.getServiceName());
                bannerBuilder.append(" [").append(fingerprint.getConfidence()).append("]");

                List<String> detectedFeatures = new ArrayList<>();

                if (responseContent != null) {
                    for (String pattern : fingerprint.getBannerPatterns()) {
                        if (responseContent.toLowerCase().contains(pattern.toLowerCase())) {
                            detectedFeatures.add("banner:" + pattern);
                            break;
                        }
                    }
                }

                for (Map.Entry<String, List<String>> entry : fingerprint.getHeaderPatterns().entrySet()) {
                    String headerValue = headers.get(entry.getKey());
                    if (headerValue != null) {
                        for (String pattern : entry.getValue()) {
                            if (headerValue.toLowerCase().contains(pattern.toLowerCase())) {
                                detectedFeatures.add("header:" + entry.getKey() + "=" + pattern);
                                break;
                            }
                        }
                    }
                }

                if (responseContent != null) {
                    for (String pattern : fingerprint.getHtmlPatterns()) {
                        try {
                            if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseContent).find()) {
                                detectedFeatures.add("content:" + pattern);
                                break;
                            }
                        } catch (Exception e) {
                            // 忽略正则表达式错误
                        }
                    }
                }

                if (!detectedFeatures.isEmpty()) {
                    bannerBuilder.append(" | Features: ").append(String.join(", ", detectedFeatures));
                }

                banner = bannerBuilder.toString();
            } else {
                // 特殊处理：如果端口是RabbitMQ常用端口但指纹识别失败
                if ((port == 15672 || port == 443 || port == 8443) &&
                        (responseContent.contains("rabbitmq") ||
                                responseContent.contains("RabbitMQ") ||
                                (serverHeader != null && serverHeader.contains("Cowboy")) ||
                                responseCode == 401)) {
                    serviceInfo = "RabbitMQ Management (Suspected)";
                    banner = "RabbitMQ Management - Detected by heuristic";
                } else if (serverHeader != null && !serverHeader.isEmpty()) {
                    banner = serverHeader;
                    serviceInfo = "Web Service";
                } else {
                    banner = "Unknown Service";
                    serviceInfo = "Unknown Service";
                }
            }

            return new ScanResult(
                    target, port, protocol,
                    serviceInfo,
                    banner, responseCode, scanType
            );

        } catch (Exception e) {
            log("[DEBUG] HTTP scan failed for " + target + ":" + port + " (" + protocol + "): " + e.getMessage());
            return null;
        }
    }

    // 尝试RabbitMQ特定端点
    private ScanResult tryRabbitMQEndpoints(String target, int port, String protocol, String scanType) {
        try {
            // 设置SSL信任
            if (protocol.equals("https")) {
                setupSSLTrust();
            }

            // 尝试API端点
            String apiUrlStr = protocol + "://" + target + ":" + port + "/api/overview";
            URL apiUrl = new URL(apiUrlStr);
            HttpURLConnection apiConnection;

            if (protocol.equals("https")) {
                apiConnection = (HttpsURLConnection) apiUrl.openConnection();
            } else {
                apiConnection = (HttpURLConnection) apiUrl.openConnection();
            }

            apiConnection.setRequestMethod("GET");
            apiConnection.setConnectTimeout(3000);
            apiConnection.setReadTimeout(5000);
            apiConnection.setRequestProperty("User-Agent", "BurpPortScanner/1.0");

            int apiResponseCode = apiConnection.getResponseCode();
            String contentType = apiConnection.getHeaderField("content-type");

            if (apiResponseCode == 200 || apiResponseCode == 401) {
                // 即使是401也说明是RabbitMQ API
                if (contentType != null && contentType.contains("application/json")) {
                    // 读取API响应
                    BufferedReader apiReader = new BufferedReader(new InputStreamReader(apiConnection.getInputStream()));
                    StringBuilder apiResponse = new StringBuilder();
                    String apiLine;
                    while ((apiLine = apiReader.readLine()) != null) {
                        apiResponse.append(apiLine);
                    }
                    apiReader.close();

                    if (apiResponse.toString().contains("rabbitmq") ||
                            apiResponse.toString().contains("management_version") ||
                            apiResponse.toString().contains("erlang_version")) {
                        apiConnection.disconnect();
                        return new ScanResult(
                                target, port, protocol,
                                "RabbitMQ Management API",
                                "RabbitMQ Management API detected (API endpoint)",
                                apiResponseCode, scanType
                        );
                    }
                }
            }
            apiConnection.disconnect();

            // 尝试管理界面
            String mgmtUrlStr = protocol + "://" + target + ":" + port + "/";
            URL mgmtUrl = new URL(mgmtUrlStr);
            HttpURLConnection mgmtConnection;

            if (protocol.equals("https")) {
                mgmtConnection = (HttpsURLConnection) mgmtUrl.openConnection();
            } else {
                mgmtConnection = (HttpURLConnection) mgmtUrl.openConnection();
            }

            mgmtConnection.setRequestMethod("GET");
            mgmtConnection.setConnectTimeout(3000);
            mgmtConnection.setReadTimeout(5000);
            mgmtConnection.setRequestProperty("User-Agent", "Mozilla/5.0 (compatible; BurpPortScanner/1.0)");

            int mgmtResponseCode = mgmtConnection.getResponseCode();

            // 读取响应内容
            String mgmtContent = "";
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(mgmtConnection.getInputStream()));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 50) {
                    responseBuilder.append(line).append("\n");
                    lineCount++;
                }
                reader.close();
                mgmtContent = responseBuilder.toString();
            } catch (Exception e) {
                // 忽略错误
            }

            mgmtConnection.disconnect();

            // 检查是否是RabbitMQ管理界面
            if (mgmtContent.contains("RabbitMQ") || mgmtContent.contains("rabbitmq") ||
                    mgmtContent.contains("management") || mgmtResponseCode == 401) {
                return new ScanResult(
                        target, port, protocol,
                        "RabbitMQ Management",
                        "RabbitMQ Management Interface detected",
                        mgmtResponseCode, scanType
                );
            }

        } catch (Exception e) {
            // 忽略端点测试错误
        }

        return null;
    }

    // 设置SSL信任所有证书
    private void setupSSLTrust() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            // 忽略SSL设置错误
        }
    }

    // 指纹识别方法
    private ServiceFingerprint identifyService(String target, int port, String protocol, String responseData, Map<String, String> headers) {
        if (fingerprintLibrary == null) {
            return null;
        }

        ServiceFingerprint result = fingerprintLibrary.identifyService(target, port, protocol, responseData, headers);

        // 调试日志
        if (result != null) {
            log("[DEBUG] Fingerprint matched: " + result.getServiceName() + " with confidence: " + result.getConfidence());
        } else {
            log("[DEBUG] No fingerprint matched for " + target + ":" + port + " (" + protocol + ")");
            if (responseData != null && responseData.length() > 0) {
                String preview = responseData.substring(0, Math.min(300, responseData.length()));
                log("[DEBUG] Response preview: " + preview.replace("\n", " "));
            }
            if (headers != null && !headers.isEmpty()) {
                log("[DEBUG] Headers: " + headers.toString());
            }
        }

        return result;
    }

    // 扫描协议目标
    private ScanResult scanProtocolTarget(String target, int port, String protocol, String scanType) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(target, port), 3000);  // 增加超时
            socket.setSoTimeout(3000);

            String banner = "";
            String serviceInfo = protocol.toUpperCase() + " Service";

            try {
                InputStream input = socket.getInputStream();
                OutputStream output = socket.getOutputStream();

                byte[] response = readBanner(input, output, protocol);
                if (response != null && response.length > 0) {
                    banner = new String(response, StandardCharsets.UTF_8).trim();

                    ServiceFingerprint fingerprint = identifyService(target, port, protocol, banner, new HashMap<>());
                    if (fingerprint != null) {
                        serviceInfo = fingerprint.getServiceName();
                        banner = fingerprint.getServiceName() + " [" + fingerprint.getConfidence() + "]";
                    }
                }
            } catch (Exception e) {
                banner = "Connected";
            }

            return new ScanResult(
                    target, port, protocol, serviceInfo,
                    banner, 200, scanType
            );

        } catch (Exception e) {
            log("[DEBUG] Protocol scan failed for " + target + ":" + port + " (" + protocol + "): " + e.getMessage());
            return null;
        }
    }

    // 读取banner信息的方法
    private byte[] readBanner(InputStream input, OutputStream output, String protocol) {
        try {
            switch (protocol.toLowerCase()) {
                case "ssh":
                    return readWithTimeout(input, 5000);
                case "ftp":
                    return readWithTimeout(input, 3000);
                case "smtp":
                    return readWithTimeout(input, 3000);
                case "mysql":
                    output.write(new byte[] {0x0a, 0x00, 0x00, 0x00, 0x0a});
                    return readWithTimeout(input, 3000);
                case "redis":
                    output.write("PING\r\n".getBytes());
                    return readWithTimeout(input, 3000);
                default:
                    return readWithTimeout(input, 2000);
            }
        } catch (Exception e) {
            return null;
        }
    }

    // 带超时的读取方法
    private byte[] readWithTimeout(InputStream input, int timeout) throws IOException {
        byte[] buffer = new byte[4096];
        int bytesRead = 0;
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < timeout) {
            if (input.available() > 0) {
                int read = input.read(buffer, bytesRead, buffer.length - bytesRead);
                if (read == -1) break;
                bytesRead += read;
                if (bytesRead >= buffer.length) break;
            } else {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }

        if (bytesRead > 0) {
            byte[] result = new byte[bytesRead];
            System.arraycopy(buffer, 0, result, 0, bytesRead);
            return result;
        }
        return null;
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

            if (task.protocol.equals("http") || task.protocol.equals("https")) {
                result = scanHttpTarget(task.target, task.port, task.protocol, task.scanType);
            } else {
                result = scanProtocolTarget(task.target, task.port, task.protocol, task.scanType);
            }

            if (result != null) {
                scannedHosts.add(hostPortKey);
                scanResults.add(result);
                addResultToTable(result);
                successfulScans.incrementAndGet();
                log("[FOUND] " + task.scanType + " - " + task.target + ":" + task.port + " (" + task.protocol + ") - " + result.service);
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

    // 辅助方法
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
            tableModel.addRow(new Object[]{
                    result.host,
                    result.port,
                    result.proto,
                    result.service,
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

    private String getProtocolByPort(int port) {
        // 改进协议推断逻辑
        switch (port) {
            case 21: return "ftp";
            case 22: return "ssh";
            case 23: return "telnet";
            case 25: return "smtp";
            case 53: return "dns";
            case 80: return "http";
            case 110: return "pop3";
            case 135: return "rpc";
            case 139: return "netbios";
            case 143: return "imap";
            case 443: return "https";  // 重要：443端口使用HTTPS
            case 445: return "smb";
            case 993: return "imaps";
            case 995: return "pop3s";
            case 1433: return "mssql";
            case 1521: return "oracle";
            case 2049: return "nfs";
            case 2375: return "docker";
            case 2376: return "docker-ssl";
            case 3306: return "mysql";
            case 3389: return "rdp";
            case 5432: return "postgresql";
            case 5672: return "amqp";
            case 5900: return "vnc";
            case 6379: return "redis";
            case 873: return "rsync";
            case 11211: return "memcached";
            case 15672: return "http";  // RabbitMQ管理界面使用HTTP
            case 161: return "snmp";
            case 389: return "ldap";
            case 514: return "syslog";
            case 636: return "ldaps";
            case 27017: return "mongodb";
            case 27018: return "mongodb";
            case 50000: return "db2";
            case 50030: return "hadoop";
            case 50070: return "hadoop-hdfs";
            case 9200: return "http";
            case 8443: return "https";  // 8443端口也使用HTTPS
            default:
                if (port == 443 || port == 8443 || port == 9443 || port == 10443) {
                    return "https";
                } else if (port >= 8000 && port <= 8999) {
                    return "http";
                } else {
                    return "tcp";
                }
        }
    }

    private boolean isValidIPAddress(String host) {
        return host.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    }

    // 内部类 - 指纹识别库
    private class ServiceFingerprintLibrary {
        private List<ServiceFingerprint> fingerprints;

        public ServiceFingerprintLibrary() {
            this.fingerprints = new ArrayList<>();
        }

        public void loadFingerprintsFromFile(String filePath) throws IOException {
            fingerprints.clear();

            try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
                StringBuilder jsonContent = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonContent.append(line);
                }

                parseJsonFingerprints(jsonContent.toString());
            }
        }

        private void parseJsonFingerprints(String jsonContent) {
            try {
                // 简单的JSON解析实现
                // 移除首尾的方括号和空格
                String content = jsonContent.trim();
                if (content.startsWith("[")) {
                    content = content.substring(1);
                }
                if (content.endsWith("]")) {
                    content = content.substring(0, content.length() - 1);
                }

                // 分割各个指纹对象
                String[] fingerprintBlocks = content.split("\\},\\s*\\{");

                for (String block : fingerprintBlocks) {
                    // 修复块格式
                    String fixedBlock = block.trim();
                    if (!fixedBlock.startsWith("{")) {
                        fixedBlock = "{" + fixedBlock;
                    }
                    if (!fixedBlock.endsWith("}")) {
                        fixedBlock = fixedBlock + "}";
                    }

                    ServiceFingerprint fingerprint = parseFingerprintBlock(fixedBlock);
                    if (fingerprint != null) {
                        fingerprints.add(fingerprint);
                    }
                }
            } catch (Exception e) {
                log("Error parsing fingerprint JSON: " + e.getMessage());
            }
        }

        private ServiceFingerprint parseFingerprintBlock(String block) {
            try {
                ServiceFingerprint fingerprint = new ServiceFingerprint();

                // 解析服务名称
                if (block.contains("\"serviceName\":")) {
                    String name = extractJsonValue(block, "serviceName");
                    fingerprint.setServiceName(name);
                }

                // 解析协议
                if (block.contains("\"protocol\":")) {
                    String protocol = extractJsonValue(block, "protocol");
                    fingerprint.setProtocol(protocol);
                }

                // 解析端口
                if (block.contains("\"ports\":")) {
                    String portsStr = extractJsonArray(block, "ports");
                    List<Integer> ports = parsePortsArray(portsStr);
                    fingerprint.getPorts().addAll(ports);
                }

                // 解析banner模式
                if (block.contains("\"bannerPatterns\":")) {
                    String patternsStr = extractJsonArray(block, "bannerPatterns");
                    List<String> patterns = parseStringArray(patternsStr);
                    fingerprint.getBannerPatterns().addAll(patterns);
                }

                // 解析header模式
                if (block.contains("\"headerPatterns\":")) {
                    parseHeaderPatterns(block, fingerprint);
                }

                // 解析HTML模式
                if (block.contains("\"htmlPatterns\":")) {
                    String patternsStr = extractJsonArray(block, "htmlPatterns");
                    List<String> patterns = parseStringArray(patternsStr);
                    fingerprint.getHtmlPatterns().addAll(patterns);
                }

                // 解析置信度
                if (block.contains("\"confidence\":")) {
                    String confidence = extractJsonValue(block, "confidence");
                    fingerprint.setConfidence(confidence);
                }

                return fingerprint;

            } catch (Exception e) {
                log("Error parsing fingerprint block: " + e.getMessage());
                return null;
            }
        }

        private String extractJsonValue(String json, String key) {
            try {
                String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"";
                Pattern p = Pattern.compile(pattern);
                Matcher m = p.matcher(json);
                if (m.find()) {
                    return m.group(1);
                }
            } catch (Exception e) {
                // 忽略错误
            }
            return "";
        }

        private String extractJsonArray(String json, String key) {
            try {
                String pattern = "\"" + key + "\"\\s*:\\s*\\[([^\\]]+)\\]";
                Pattern p = Pattern.compile(pattern);
                Matcher m = p.matcher(json);
                if (m.find()) {
                    return m.group(1);
                }
            } catch (Exception e) {
                // 忽略错误
            }
            return "";
        }

        private List<Integer> parsePortsArray(String portsStr) {
            List<Integer> ports = new ArrayList<>();
            try {
                String[] portStrings = portsStr.split(",");
                for (String portStr : portStrings) {
                    try {
                        int port = Integer.parseInt(portStr.trim());
                        ports.add(port);
                    } catch (NumberFormatException e) {
                        // 忽略无效端口
                    }
                }
            } catch (Exception e) {
                // 忽略错误
            }
            return ports;
        }

        private List<String> parseStringArray(String arrayStr) {
            List<String> strings = new ArrayList<>();
            try {
                String[] stringArray = arrayStr.split(",");
                for (String str : stringArray) {
                    String cleaned = str.trim().replaceAll("^\"|\"$", "");
                    if (!cleaned.isEmpty()) {
                        strings.add(cleaned);
                    }
                }
            } catch (Exception e) {
                // 忽略错误
            }
            return strings;
        }

        private void parseHeaderPatterns(String json, ServiceFingerprint fingerprint) {
            try {
                // 简单的header模式解析
                String headerPattern = "\"headerPatterns\"\\s*:\\s*\\{([^}]+)\\}";
                Pattern p = Pattern.compile(headerPattern);
                Matcher m = p.matcher(json);
                if (m.find()) {
                    String headersStr = m.group(1);
                    String[] headerEntries = headersStr.split(",");
                    for (String entry : headerEntries) {
                        String[] parts = entry.split(":", 2);
                        if (parts.length == 2) {
                            String headerName = parts[0].trim().replaceAll("^\"|\"$", "");
                            String valuesStr = parts[1].trim();
                            List<String> values = parseStringArray(valuesStr);
                            fingerprint.getHeaderPatterns().put(headerName, values);
                        }
                    }
                }
            } catch (Exception e) {
                // 忽略错误
            }
        }

        public ServiceFingerprint identifyService(String target, int port, String protocol,
                                                  String responseData, Map<String, String> headers) {
            ServiceFingerprint bestMatch = null;
            int bestScore = 0;

            for (ServiceFingerprint fingerprint : fingerprints) {
                int score = calculateMatchScore(fingerprint, target, port, protocol, responseData, headers);
                if (score > bestScore) {
                    bestScore = score;
                    bestMatch = fingerprint;
                }
            }

            return bestScore >= 10 ? bestMatch : null;  // 降低匹配阈值
        }

        private int calculateMatchScore(ServiceFingerprint fingerprint, String target, int port,
                                        String protocol, String responseData, Map<String, String> headers) {
            int score = 0;

            // 端口匹配
            if (fingerprint.getPorts().contains(port)) {
                score += 5;
            }

            // 协议匹配
            if (fingerprint.getProtocol().equalsIgnoreCase(protocol)) {
                score += 5;
            }

            // banner模式匹配
            if (responseData != null) {
                for (String pattern : fingerprint.getBannerPatterns()) {
                    if (responseData.toLowerCase().contains(pattern.toLowerCase())) {
                        score += 20;
                        break;
                    }
                }
            }

            // HTTP头匹配
            for (Map.Entry<String, List<String>> entry : fingerprint.getHeaderPatterns().entrySet()) {
                String headerValue = headers.get(entry.getKey());
                if (headerValue != null) {
                    for (String pattern : entry.getValue()) {
                        if (headerValue.toLowerCase().contains(pattern.toLowerCase())) {
                            score += 15;
                            break;
                        }
                    }
                }
            }

            // HTML内容匹配
            if (responseData != null) {
                for (String pattern : fingerprint.getHtmlPatterns()) {
                    try {
                        if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(responseData).find()) {
                            score += 25;
                            break;
                        }
                    } catch (Exception e) {
                        // 忽略正则表达式错误
                    }
                }
            }

            return score;
        }

        public int getFingerprintCount() {
            return fingerprints.size();
        }
    }

    // 内部类
    private static class ServiceFingerprint {
        private String serviceName;
        private String protocol;
        private List<Integer> ports;
        private List<String> bannerPatterns;
        private Map<String, List<String>> headerPatterns;
        private List<String> htmlPatterns;
        private List<String> responsePatterns;
        private Map<String, List<String>> jsonPatterns;
        private String confidence;

        public ServiceFingerprint() {
            this.ports = new ArrayList<>();
            this.bannerPatterns = new ArrayList<>();
            this.headerPatterns = new HashMap<>();
            this.htmlPatterns = new ArrayList<>();
            this.responsePatterns = new ArrayList<>();
            this.jsonPatterns = new HashMap<>();
        }

        public String getServiceName() { return serviceName; }
        public void setServiceName(String serviceName) { this.serviceName = serviceName; }

        public String getProtocol() { return protocol; }
        public void setProtocol(String protocol) { this.protocol = protocol; }

        public List<Integer> getPorts() { return ports; }
        public void setPorts(List<Integer> ports) { this.ports = ports; }

        public List<String> getBannerPatterns() { return bannerPatterns; }
        public void setBannerPatterns(List<String> bannerPatterns) { this.bannerPatterns = bannerPatterns; }

        public Map<String, List<String>> getHeaderPatterns() { return headerPatterns; }
        public void setHeaderPatterns(Map<String, List<String>> headerPatterns) { this.headerPatterns = headerPatterns; }

        public List<String> getHtmlPatterns() { return htmlPatterns; }
        public void setHtmlPatterns(List<String> htmlPatterns) { this.htmlPatterns = htmlPatterns; }

        public List<String> getResponsePatterns() { return responsePatterns; }
        public void setResponsePatterns(List<String> responsePatterns) { this.responsePatterns = responsePatterns; }

        public Map<String, List<String>> getJsonPatterns() { return jsonPatterns; }
        public void setJsonPatterns(Map<String, List<String>> jsonPatterns) { this.jsonPatterns = jsonPatterns; }

        public String getConfidence() { return confidence; }
        public void setConfidence(String confidence) { this.confidence = confidence; }
    }

    private static class PortProtocol {
        int port;
        String protocol;
        PortProtocol(int port, String protocol) {
            this.port = port;
            this.protocol = protocol;
        }
    }

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
        String service;
        String banner;
        int code;
        String scanType;
        ScanResult(String host, int port, String proto, String service,
                   String banner, int code, String scanType) {
            this.host = host;
            this.port = port;
            this.proto = proto;
            this.service = service;
            this.banner = banner;
            this.code = code;
            this.scanType = scanType;
        }
    }

    // 生成默认指纹库
    private String generateDefaultFingerprints() {
        // 简化的默认指纹库
        return "[\n" +
                "  {\n" +
                "    \"serviceName\": \"RabbitMQ Management\",\n" +
                "    \"protocol\": \"http\",\n" +
                "    \"ports\": [15672, 443, 8443, 80, 8080],\n" +
                "    \"bannerPatterns\": [\"RabbitMQ\", \"rabbitmq\", \"management\"],\n" +
                "    \"headerPatterns\": {\n" +
                "      \"Server\": [\"Cowboy\", \"RabbitMQ\", \"Webmachine\"]\n" +
                "    },\n" +
                "    \"htmlPatterns\": [\"RabbitMQ Management\", \"rabbitmq\", \"management.rabbitmq\", \"login.*rabbitmq\"],\n" +
                "    \"confidence\": \"high\"\n" +
                "  }\n" +
                "]";
    }
}