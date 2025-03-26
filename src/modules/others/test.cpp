#include "globals.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "clicker.h"
#include "core/utils.h"
#include "modules/others/test.h"

void testkeyboard(){
  String testkeyboard = keyboard("100",4,"test string entering");
  Serial.println(testkeyboard);
  displayTextLine(testkeyboard);
  delay(2000);
}
void testfilepicker(){
    FS *fs = nullptr;
 String filepath = loopSD(*fs, true, "*", "/");
    if (filepath.isEmpty() || check(EscPress)) return;

    // Check file size
    File file = fs->open(filepath);
    if (!file) return;

    size_t fileSize = file.size();
    file.close();
    Serial.println(fileSize);
    Serial.println(filepath);
    displayTextLine(String(fileSize));
    displayTextLine(filepath);
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
void testmenu(){
  options = {
    {"testkeyboard", [=]() { testkeyboard();}},
    {"testfilepicker", [=]() { testfilepicker();}},
    {"testintpicker", [=]() { testintpicker();}},
  };
  addOptionToMainMenu();
  loopOptions(options);
}

void test_setup(){
    testmenu();
}
