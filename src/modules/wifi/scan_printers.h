#ifndef __SCAN_PRINTERS_H__
#define __SCAN_PRINTERS_H__

#include <WiFi.h>
#include "scan_hosts.h"

// sets number of maximum of pending requests to table size
#define ARP_MAXPENDING ARP_TABLE_SIZE

void scanPrinterPorts(const Host &host);
void printerReadArpTable(netif *iface);

void scanForPrinters();

#endif // __SCAN_PRINTERS_H__



