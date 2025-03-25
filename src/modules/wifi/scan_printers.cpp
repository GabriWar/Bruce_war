#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/wifi_common.h"
#include "clients.h"
#include "core/utils.h"
#include "scan_printers.h"

struct printerHostPort {
    String ip;
    int port;
};
static std::vector<printerHostPort> printerOpenPortsList;

struct PrintPortScan { //struct pra holdar info das portas
    int port;
    unsigned long startTime;
    WiFiClient client;
    bool inProgress;
};
std::map<int, std::string> printerPortServices = {
    {515, "LPD, Line Printer Daemon"},
    {631, "IPP, Internet Printing Protocol, CUPS"},
    {9100, "Raw Printing (JetDirect)"},
};


void scanPrinterPorts(const Host& host) {
    const int MAX_SIMULTANEOUS = 10;  // Number of simultaneous connection attempts
    const int TIMEOUT_MS = 1000;      // Timeout for each connection attempt
    int scannedPorts = 0;
    int totalPorts = printerPortServices.size();

    std::vector<PrintPortScan> scans(MAX_SIMULTANEOUS);
    auto portIter = printerPortServices.begin();
    int activeScanCount = 0;

    // Initialize scans
    for(auto& scan : scans) {
        scan.inProgress = false;
    }

    bool scanCanceled = false;
    unsigned long lastUpdate = 0;
    while((portIter != printerPortServices.end() || activeScanCount > 0) && !scanCanceled) {
        // Update display every 500ms
        if (millis() - lastUpdate > 500) {
            displayRedStripe("Scanning " + host.ip.toString() + " - Port " + String(scannedPorts) + " of " + String(totalPorts),
                           getComplementaryColor2(bruceConfig.priColor), bruceConfig.priColor);
            lastUpdate = millis();
        }

        // Start new scans if possible
        while(activeScanCount < MAX_SIMULTANEOUS && portIter != printerPortServices.end()) {
            for(auto& scan : scans) {
                if(!scan.inProgress) {
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
        for(auto& scan : scans) {
            if(scan.inProgress) {
                // Check if connected
                if(scan.client.connected()) {
                    printerOpenPortsList.push_back({host.ip.toString(), scan.port}); // Save the open port and host
                    scan.client.stop();
                    scan.inProgress = false;
                    activeScanCount--;
                }
                // Check for timeout
                else if(millis() - scan.startTime > TIMEOUT_MS) {
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
TickType_t printerArpRequestDelay = 20u / portTICK_PERIOD_MS; // can be relatively low, helps to not overwhelm the stream

void printerReadArpTable(netif * iface) {
  for( uint32_t i = 0; i < ARP_TABLE_SIZE; ++i ){
    ip4_addr_t* ip_ret;
    eth_addr* eth_ret;
    if( etharp_get_entry(i, &ip_ret, &iface, &eth_ret) ){
      hostslist.emplace_back(ip_ret, eth_ret);
    }
  }
  etharp_cleanup_netif(iface);
}



void scanForPrinters() {
    if(!wifiConnected) {
        displayTextLine("Please connect to WiFi first");
        delay(2000);
        return;
    }

    bool doScan = true;
    if(!wifiConnected) doScan=wifiConnectMenu();

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
        void * netif = nullptr;
        tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA, &netif);
        struct netif *net_iface = (struct netif *)netif;
        etharp_cleanup_netif(net_iface); // to avoid gateway duplication


        // send arp requests, read table each ARP_TABLE_SIZE requests
        uint16_t tableReadCounter = 0;
        uint32_t hostsScanned = 0;
        const uint32_t totalHosts = broadcast - networkAddress - 1;
        static uint32_t lastUpdate = 0;

        for( uint32_t ip_le = networkAddress + 1; ip_le < broadcast; ++ip_le ){
          if( ip_le == localIp ) continue;

          ip4_addr_t ip_be{htonl(ip_le)}; // big endian

          hostsScanned++;
          if (millis() - lastUpdate > 500) { // Update display every 500ms
            displayRedStripe("Probing " + String(hostsScanned) + " of " + String(totalHosts) + " hosts", getComplementaryColor2(bruceConfig.priColor), bruceConfig.priColor);
            lastUpdate = millis();
          }

          err_t res = etharp_request(net_iface, &ip_be);

          if( res != ERR_OK ){
            Serial.println("Arp req for: " + IPAddress(ip_be.addr).toString() + "failed with ec: " + res);
          } else {
            ++tableReadCounter;
          }

          vTaskDelay(printerArpRequestDelay);

          // read table if we sent ARP_TABLE_SIZE requests
          if( tableReadCounter == ARP_TABLE_SIZE ){
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
        for (const auto& host : hostslist) {
            scanPrinterPorts(host);
        }

        // Display results
        //set black background
        tft.fillScreen(TFT_BLACK);
        tft.setCursor(8,30);
        tft.println("Scan results:");
        for (const auto& entry : printerOpenPortsList) {
            tft.println("Host: " + entry.ip + " Port: " + String(entry.port));
        }

        delay(5000); // Display results for 5 seconds before returning to the menu
    }
    hostslist.clear();
}
