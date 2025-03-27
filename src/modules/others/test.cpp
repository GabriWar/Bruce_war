#include "modules/others/test.h"
#include "clicker.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "globals.h"
#include <FS.h>
#include <SD.h>

void testkeyboard() {
    String testkeyboard = keyboard("100", 4, "test string entering");
    Serial.println(testkeyboard);
    displayTextLine(testkeyboard);
    delay(2000);
}
void progressbar(int progress, size_t total, String message) {
  int barWidth = map(progress, 0, total, 0, tftWidth-40);
  if(barWidth <3) {
    tft.fillRect(6, 27, tftWidth-12, tftHeight-33, bruceConfig.bgColor);
    tft.drawRect(18, tftHeight - 47, tftWidth-36, 17, bruceConfig.priColor);
    if (!message.isEmpty()) {
    displayRedStripe(message, TFT_WHITE, bruceConfig.priColor);
  }
  tft.fillRect(20, tftHeight - 45, barWidth, 13, bruceConfig.priColor);
}
}


void testfilepicker() {
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

    if (!fs) return; // Safety check

    String filepath = loopSD(*fs, true, "*", "/");
    if (filepath.isEmpty() || check(EscPress)) return;

    // Check file size
    File file = fs->open(filepath);
    if (!file) return;
    size_t fileSize = file.size();
    file.close();
    Serial.println(fileSize);
    Serial.println(filepath);
    displayTextLine("SIZE: " + String(fileSize));
    delay(2000);
    displayTextLine("PATH: " + filepath);
    delay(2000);
}
void testintpicker() {
    int picked;
    options = {};
    for (int i = 0; i < 10; i++) {
        String tmp = String(i < 10 ? "0" : "") + String(i);
        options.push_back({tmp.c_str(), [&]() { delay(1); }});
    }

    picked = loopOptions(options, false, true, "pick a number");
    options.clear();
    Serial.println(picked);
    displayTextLine(String(picked));
    delay(2000);
}

void testprogressbar() {
    for (int i = 0; i < 100; i++) {
        progressbar(i, 100, "processing");
        delay(10);
    }
}




void testinteractivebar() {
    int progress = 0;
    bool redraw = true;

    while (!check(EscPress)) {

        if (redraw) {
            progressbar(progress, 100,"");
            drawMainBorderWithTitle("Selected: " + String(progress) + "%");
            redraw = false;
        }

        if (check(PrevPress)) {
            if (progress >= 0 && progress < 100) {
                progress += 1;
                redraw = true;
            }
        }
        if (check(NextPress)) {
            if (progress > 0 && progress <= 100) {
                progress -= 1;
                redraw = true;
            }
        }
        if (check(SelPress)) {
            displayTextLine("Selected: " + String(progress) + "%");
            delay(2000);
            return;
        }
    }
    while (check(EscPress)) yield();
}
bool returntomainmenu = false;
void submenu() {
    options = {
        {"TEST KEYBOARD",        [=]() { testkeyboard(); }      },
        {"TEST FILE PICKER",     [=]() { testfilepicker(); }    },
        {"TEST INT PICKER",      [=]() { testintpicker(); }     },
        {"TEST PROGRESS BAR",    [=]() { testprogressbar(); }   },
        {"TEST INTERACTIVE BAR", [=]() { testinteractivebar(); }}
    };
    addOptionToMainMenu();
    loopOptions(options);
}
void testmenu() {
    options = {
        {"KEYBOARD",        [=]() { testkeyboard(); }      },
        {"FILE PICKER",     [=]() { testfilepicker(); }    },
        {"INT PICKER",      [=]() { testintpicker(); }     },
        {"PROGRESS BAR",    [=]() { testprogressbar(); }   },
        {"INTERACTIVE BAR", [=]() { testinteractivebar(); }},
        {"SUBMENU",         [=]() { submenu(); }           }
    };

    addOptionToMainMenu();
    loopOptions(options);
}

void test_setup() {
    while (true) {
        Serial.println("test_setup");
        testmenu();
        if (check(EscPress) or returnToMenu) break;
        Serial.println("test_setup done");
    }
}
