
#include <stdio.h>
#include <string.h>
#include <WiFi.h>
#include "core/net_utils.h"

#include "lwip/etharp.h"
// sets number of maximum of pending requests to table size
#define ARP_MAXPENDING ARP_TABLE_SIZE


void scanForPrinters();

