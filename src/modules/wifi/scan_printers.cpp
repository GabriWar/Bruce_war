#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/wifi_common.h"
#include "clients.h"
#include "core/utils.h"
#include "scan_printers.h"
#include <SD.h>

struct printerHostPort {
    String ip;
    int port;
};
static std::vector<printerHostPort> printerOpenPortsList;

struct PrintPortScan { // struct pra holdar info das portas
    int port;
    unsigned long startTime;
    WiFiClient client;
    bool inProgress;
};
std::map<int, std::string> printerPortServices = {
    {515,  "LPD, Line Printer Daemon"             },
    {631,  "IPP, Internet Printing Protocol, CUPS"},
    {9100, "Raw Printing (JetDirect)"             },
};

static std::vector<Option> savedPrinterOptions; // Changed from MenuOption to Option

void scanPrinterPorts(const Host &host, int currentHost, int totalHosts) {
    const int MAX_SIMULTANEOUS = 10; // Number of simultaneous connection attempts
    const int TIMEOUT_MS = 1000;     // Timeout for each connection attempt
    int scannedPorts = 0;
    int totalPorts = printerPortServices.size();

    std::vector<PrintPortScan> scans(MAX_SIMULTANEOUS);
    auto portIter = printerPortServices.begin();
    int activeScanCount = 0;

    // Initialize scans
    for (auto &scan : scans) { scan.inProgress = false; }

    bool scanCanceled = false;
    unsigned long lastUpdate = 0;
    while ((portIter != printerPortServices.end() || activeScanCount > 0) && !scanCanceled) {
        // Update display every 500ms
        if (millis() - lastUpdate > 500) {
            displayRedStripe(
                "Scanning " + host.ip.toString() + " (" + String(totalHosts - currentHost) +
                    " hosts remaining)",
                getComplementaryColor2(bruceConfig.priColor),
                bruceConfig.priColor
            );
            lastUpdate = millis();
        }

        // Start new scans if possible
        while (activeScanCount < MAX_SIMULTANEOUS && portIter != printerPortServices.end()) {
            for (auto &scan : scans) {
                if (!scan.inProgress) {
                    scan.port = portIter->first;
                    scan.startTime = millis();
                    scan.inProgress = true;
                    scan.client.connect(host.ip, scan.port);
                    activeScanCount++;
                    portIter++;
                    break;
                }
            }
        }

        // Check ongoing scans
        for (auto &scan : scans) {
            if (scan.inProgress) {
                // Check if connected
                if (scan.client.connected()) {
                    printerOpenPortsList.push_back({host.ip.toString(), scan.port}
                    ); // Save the open port and host
                    scan.client.stop();
                    scan.inProgress = false;
                    activeScanCount--;
                }
                // Check for timeout
                else if (millis() - scan.startTime > TIMEOUT_MS) {
                    scan.client.stop();
                    scan.inProgress = false;
                    activeScanCount--;
                    scannedPorts++;
                }
            }
        }
        yield(); // Allow other tasks to run
    }
}

static std::vector<Host> hostslist;

// TODO: resolve clients name when in host mode through dhcp

// TODO: move to a config
TickType_t printerArpRequestDelay =
    20u / portTICK_PERIOD_MS; // can be relatively low, helps to not overwhelm the stream

void printerReadArpTable(netif *iface) {
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; ++i) {
        ip4_addr_t *ip_ret;
        eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &iface, &eth_ret)) { hostslist.emplace_back(ip_ret, eth_ret); }
    }
    etharp_cleanup_netif(iface);
}

void sendRawPrint(const String &ip, const String &data) {
    WiFiClient client;
    displayTextLine("Connecting to printer...");
    if (client.connect(ip.c_str(), 9100)) {
        displayTextLine("Sending print job...");
        client.print(data);
        client.flush();
        delay(100); // Give some time for the data to be sent
        client.stop();
        displayTextLine("Print job sent successfully");
    } else {
        displayTextLine("Failed to connect to printer");
    }

    delay(2000);
    yield(); // Allow other tasks to run
}

// Helper function to print a file
void printFile(const String &ip, const String &filepath, FS &fs) {
    File file = fs.open(filepath);
    if (!file) {
        displayTextLine("Failed to open file");
        delay(2000);
        return;
    }

    String fileContent;
    while (file.available()) { fileContent += (char)file.read(); }
    file.close();

    sendRawPrint(ip, fileContent);
    delay(2000);
}

// Helper function to handle file selection and printing
void handleFilePrint(const String &ip) {
    FS *fs = nullptr;

    // Select storage (SD Card or LittleFS)
    options = {
        {"SD Card",  [&fs]() { fs = &SD; }      },
        {"LittleFS", [&fs]() { fs = &LittleFS; }}
    };
    if (!setupSdCard()) {
        options.erase(options.begin()); // Remove SD Card option if not available
    }
    loopOptions(options);

    if (!fs) return;

    // Select file
    String filepath = loopSD(*fs, true, "*", "/");
    if (filepath.isEmpty() || check(EscPress)) return;

    // Check file size
    File file = fs->open(filepath);
    if (!file) return;

    size_t fileSize = file.size();
    file.close();

    if (fileSize > 50 * 1024 * 1024) { // 50MB
        displayTextLine("Warning: File size > 50MB");
        options = {
            {"Yes, continue", [&ip, &filepath, fs]() { printFile(ip, filepath, *fs); }},
            {"No, select another", []() {}}
        };
        loopOptions(options);
        return;
    }

    printFile(ip, filepath, *fs);
}

void restorePrinterMenu() {
    options = savedPrinterOptions;
    loopOptions(options);
}

void handlePrinting(const String &ip) {
    while (!check(EscPress)) {
        options = {
            {"Print Text",
             [&ip]() {
                 String text = keyboard("", 1000, "Enter text to print:");
                 if (!text.isEmpty()) {
                     sendRawPrint(ip, text + "\n\f");
                     delay(2000);
                 }
             }},
            {"Print File", [&ip]() { handleFilePrint(ip); }},
            {"Back", []() {
                while (check(EscPress)) yield();
                return;  // This will exit the while loop
            }}
        };

        loopOptions(options);
    }
}

void scanForPrinters() {
    bool doScan = true;
    if (!wifiConnected) doScan = wifiConnectMenu();

    if (doScan) {
        hostslist.clear();
        printerOpenPortsList.clear();

        // IPAddress uint32_t op returns number in big-endian
        // for simplicity of iteration and arithmetics convert to little-endian
        const uint32_t localIp = ntohl(WiFi.localIP());
        const IPAddress gateway = WiFi.gatewayIP();
        const uint32_t subnetMask = ntohl(WiFi.subnetMask());
        const uint32_t networkAddress = ntohl(gateway) & subnetMask;
        const uint32_t broadcast = networkAddress | ~subnetMask;

        // get iface
        void *netif = nullptr;
        tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, &netif);
        struct netif *net_iface = (struct netif *)netif;
        etharp_cleanup_netif(net_iface); // to avoid gateway duplication

        // send arp requests, read table each ARP_TABLE_SIZE requests
        uint16_t tableReadCounter = 0;
        uint32_t hostsScanned = 0;
        const uint32_t totalHosts = broadcast - networkAddress - 1;
        static uint32_t lastUpdate = 0;

        for (uint32_t ip_le = networkAddress + 1; ip_le < broadcast; ++ip_le) {
            if (ip_le == localIp) continue;

            ip4_addr_t ip_be{htonl(ip_le)}; // big endian

            hostsScanned++;
            if (millis() - lastUpdate > 500) { // Update display every 500ms
                displayRedStripe(
                    "Scanning " + String(hostsScanned) + " of " + String(totalHosts) + " hosts",
                    getComplementaryColor2(bruceConfig.priColor),
                    bruceConfig.priColor
                );
                lastUpdate = millis();
            }

            err_t res = etharp_request(net_iface, &ip_be);

            if (res != ERR_OK) {
                Serial.println("Arp req for: " + IPAddress(ip_be.addr).toString() + "failed with ec: " + res);
            } else {
                ++tableReadCounter;
            }

            vTaskDelay(printerArpRequestDelay);

            // read table if we sent ARP_TABLE_SIZE requests
            if (tableReadCounter == ARP_TABLE_SIZE) {
                printerReadArpTable(net_iface);
                tableReadCounter = 0;
            }
        }

        if (hostslist.empty()) {
            tft.println("No hosts found");
            delay(2000);
            return;
        }

        // Automatically scan each host for open ports
        int hostIndex = 0;
        for (const auto &host : hostslist) {
            scanPrinterPorts(host, hostIndex, hostslist.size());
            hostIndex++;
        }

        if (printerOpenPortsList.empty()) {
            displayTextLine("No printers found");
            while (!check(AnyKeyPress)) yield();
            while (check(AnyKeyPress)) yield();
            return;
        }

        // Group ports by host
        std::map<String, std::vector<int>> hostPorts;
        for (const auto &entry : printerOpenPortsList) { hostPorts[entry.ip].push_back(entry.port); }

        // Create menu options
        options = {};
        for (const auto &host : hostslist) {
            auto it = hostPorts.find(host.ip.toString());
            if (it != hostPorts.end()) {
                String hostInfo = host.ip.toString();
                if (host.ip == WiFi.gatewayIP()) { hostInfo += " (GTW)"; }
                hostInfo += " [" + host.mac + "] (";

                // Add open printer ports
                for (size_t i = 0; i < it->second.size(); i++) {
                    if (i > 0) hostInfo += ",";
                    hostInfo += String(it->second[i]);
                    if (printerPortServices.count(it->second[i])) {
                        hostInfo += ":" + String(printerPortServices[it->second[i]].c_str());
                    }
                }
                hostInfo += ")";

                options.emplace_back(strdup(hostInfo.c_str()), [hostInfo, host, &hostPorts]() {
                    // Check if the host has port 9100 open
                    auto it = hostPorts.find(host.ip.toString());
                    bool has9100 = false;
                    if (it != hostPorts.end()) {
                        has9100 = std::find(it->second.begin(), it->second.end(), 9100) != it->second.end();
                    }

                    if (has9100) {
                        // Save the current printer menu options before going to file selection
                        savedPrinterOptions = options;
                        handlePrinting(host.ip.toString());
                    } else {
                        displayTextLine("Port 9100 not open on this host!");
                        delay(2000);
                    }
                });
            }
        }

        addOptionToMainMenu();
        loopOptions(options);

        // Clean up allocated memory
        for (auto &opt : options) {
            if (strcmp(opt.label.c_str(), "Main Menu") != 0) free((void *)opt.label.c_str());
        }
        options.clear();
    }
    hostslist.clear();
}
