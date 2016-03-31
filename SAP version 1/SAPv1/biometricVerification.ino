// BIOMETRIC FUNCTIONS

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

/* Is client currently verified? */
bool currentlyVerified() {
  // Is verifiedExpiration less than millis() ?
  return hasBeenVerified && verifiedExpiration < millis();
};

/* Is client currently blocked? */
bool currentlyBlocked() {
  return false;
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
