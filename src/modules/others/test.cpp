#include "globals.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "clicker.h"
#include "core/utils.h"
#include "modules/others/test.h"
#include <SD.h>
#include <FS.h>

void testkeyboard(){
  String testkeyboard = keyboard("100",4,"test string entering");
  Serial.println(testkeyboard);
  displayTextLine(testkeyboard);
  delay(2000);
}
void testfilepicker(){
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

    if (!fs) return;  // Safety check

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
void testintpicker(){
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

void testprogressbar(){
  for (int i = 0; i < 100; i++) {
    progressHandler(i, 100, "progressing");
    delay(10);
  }
}

void testinteractivebar(){
  int progress = 0;

  while (!check(EscPress)) {
      if (check(PrevPress)) { if (progress >= 0 and progress <100) progress += 5; }
      if (check(NextPress)) { if (progress > 0 and progress <= 100) progress -= 5; }
      if (check(SelPress)) {
          displayTextLine("Selected: " + String(progress) + "%");
          delay(2000);
          return;
      }
    progressHandler(progress, 100, "select =" + String(progress) + "%");
    delay(10);
  }
  while(check(EscPress)) yield();
}
bool returntomainmenu = false;
void testmenu(){
  while (!returntomainmenu) {
    options = {
      {"KEYBOARD", [=]() { testkeyboard();}},
      {"FILE PICKER", [=]() { testfilepicker();}},
      {"INT PICKER", [=]() { testintpicker();}},
      {"PROGRESS BAR", [=]() { testprogressbar();}},
      {"INTERACTIVE BAR", [=]() { testinteractivebar();}}
    };
    addOptionToMainMenu();
    loopOptions(options);
  }
  returntomainmenu = false;
}

void test_setup(){
  while(true){
    testmenu();
    if (check(EscPress)){ break;}
  }
}
