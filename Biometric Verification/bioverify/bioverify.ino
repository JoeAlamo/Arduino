#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <SPI.h>

// FUNCTION DEFINITIONS
bool currentlyVerified();
bool currentlyBlocked();
bool scanFingerprint();
bool convertFingerprintToTemplate();
bool verifyFingerprint(uint16_t fingerprintID);
void getStoredAuthenticationKey(uint8_t *akBuf, uint16_t akBufSize);
void exitProgram();
void printHex(const uint8_t *input, uint16_t len);

// FINGERPRINT SENSOR VARIABLES
SoftwareSerial mySerial(2,3);
Adafruit_Fingerprint fingerprintSensor = Adafruit_Fingerprint(&mySerial);
uint16_t fingerprintID = 1;

// RUN ONCE
void setup() {
  Serial.begin(9600);
  fingerprintSensor.begin(57600);

  // Check that fingerprint sensor is connected
  if (fingerprintSensor.verifyPassword()) {
    Serial.println("Fingerprint sensor is connected.");
  } else {
    Serial.println("Fingerprint sensor is not connected. Reconnect and restart.");
    exitProgram();
  }

  Serial.println("Place valid fingerprint when ready.");
}

// MAIN PROGRAM LOOP
void loop() {
  while (!currentlyVerified() && !currentlyBlocked()) {
    if (scanFingerprint() && convertFingerprintToTemplate()) {
      if (verifyFingerprint(fingerprintID)) {
        Serial.println("Your fingerprint matched.");
        uint8_t authenticationKey[32] = {0};
        getStoredAuthenticationKey(authenticationKey, 32);
        Serial.print("Key:");
        printHex(authenticationKey, 32);
      } else {
        Serial.println("Your fingerprint didn't match. Try again.");
      }
    } else {
      delay(50);
    }
  }
}

// FUNCTIONS

/* Is client currently verified? */
bool currentlyVerified() {
  return false;
};

/* Is client currently blocked? */
bool currentlyBlocked() {
  return false;
};

/* Perform initial scan of fingerprint */
bool scanFingerprint() {
  uint8_t result = fingerprintSensor.getImage();
  switch (result) {
    case FINGERPRINT_OK:
      return true;
    case FINGERPRINT_NOFINGER:
      return false;
    default:
      Serial.println("Error scanning, please retry.");
      return false;
  }
};

/* Attempt to convert image to template */
bool convertFingerprintToTemplate() {
  uint8_t result = fingerprintSensor.image2Tz();
  switch (result) {
    case FINGERPRINT_OK:
      return true;
    default:
      Serial.println("Error scanning, please retry.");
      return false;
  }
};

/* Perform biometric verification */
bool verifyFingerprint(uint16_t fingerprintID) {
  uint8_t result = fingerprintSensor.fingerFastSearch();
  switch (result) {
    case FINGERPRINT_OK:
      if (fingerprintSensor.fingerID == fingerprintID) {
        return true;
      }
    default:
      return false;
  }
};

/* Retrieve authentication key into akBuf */
void getStoredAuthenticationKey(uint8_t *akBuf, uint16_t akBufSize) {
  uint8_t storedAuthenticationKey[] = {
    0x6c, 0x44, 0x07, 0xb5, 0x44, 0xbf, 0x3d, 0x1f,
    0xb8, 0xbc, 0x2f, 0x2e, 0x43, 0x6e, 0xc0, 0x66,
    0x8c, 0xcc, 0xfe, 0x6d, 0x94, 0x8b, 0xed, 0xd7,
    0x54, 0x3c, 0xe8, 0x12, 0x46, 0xdc, 0xb0, 0x43
  };
  uint16_t len = 32, i;

  if (akBufSize < len) {
    Serial.println("Key release failure");
    exitProgram();
  }

  for (i = 0; i < akBufSize; i++) {
    akBuf[i] = storedAuthenticationKey[i];
  }

  Serial.println("Key released.");
};

/* Emulate exiting of program */
void exitProgram() {
  // Clear up any variables
  while(1);
}

/* Print contents of input in hexadecimal format */
void printHex(const uint8_t *input, uint16_t len) {
 for (uint16_t i=0; i < len; i++) {
    if (i % 8 == 0) {
      Serial.println();
    }
    Serial.print("0x");
    if (input[i] < 16) {
      Serial.print('0'); 
    }
    Serial.print(input[i], HEX);
    if (i+1 != len) {
      Serial.print(", ");
    } else {
      Serial.println();
    }
 }
}


