#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <SPI.h>

// FUNCTION DEFINITIONS
bool currentlyVerified();
bool currentlyBlocked();
bool scanFingerprint();
bool convertFingerprintToTemplate();
bool verifyFingerprint(int fingerprintID);
void getStoredAuthenticationKey(uint8_t *akBuf, int akBufSize);

// FINGERPRINT SENSOR VARIABLES
SoftwareSerial mySerial(2,3);
Adafruit_Fingerprint fingerprintSensor = Adafruit_Fingerprint(&mySerial);
int fingerprintID = 1;

// RUN ONCE
void setup() {
  Serial.begin(9600);
  fingerprintSensor.begin(57600);

  // Check that fingerprint sensor is connected
  if (fingerprintSensor.verifyPassword()) {
    Serial.println("Fingerprint sensor is connected.");
  } else {
    Serial.println("Fingerprint sensor is not connected. Reconnect and restart.");
    while(1);
  }

  Serial.println("Place valid fingerprint when ready.");
}

// MAIN PROGRAM LOOP
void loop() {
  while (!currentlyVerified() && !currentlyBlocked()) {
    if (scanFingerprint() && convertFingerprintToTemplate()) {
      if (verifyFingerprint(fingerprintID) {
        Serial.println("Your fingerprint matched.");
        uint8_t authenticationKey[32] = {0};
        getStoredAuthenticationKey(authenticationKey, 32);
      } else {
        Serial.println("Your fingerprint didn't match. Try again.");
      }
    } else {
      delay(50);
    }
  }
}

// FUNCTIONS

bool currentlyVerified() {
  return false;
};

bool currentlyBlocked() {
  return false;
};

bool scanFingerprint() {
  ;
};

bool convertFingerprintToTemplate() {
  ;
};

bool verifyFingerprint(int fingerprintID) {
  ;
};

void getStoredAuthenticationKey(uint8_t *akBuf, int akBufSize) {
  ;
};

