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
  // Have we been verified and is verifiedExpiration in the future?
  return hasBeenVerified && verifiedExpiration > millis();
};

/* Is client currently blocked? */
bool currentlyBlocked() {
  return false;
};

/* Retrieve authentication key and key derivation key into CryptoKeys struct */
void getStoredKeys(CryptoKeys *cryptoKeys, uint16_t keyLens) {
  uint8_t storedAuthenticationKey[] = {
    0x6c, 0x44, 0x07, 0xb5, 0x44, 0xbf, 0x3d, 0x1f,
    0xb8, 0xbc, 0x2f, 0x2e, 0x43, 0x6e, 0xc0, 0x66,
    0x8c, 0xcc, 0xfe, 0x6d, 0x94, 0x8b, 0xed, 0xd7,
    0x54, 0x3c, 0xe8, 0x12, 0x46, 0xdc, 0xb0, 0x43
  };
  uint8_t storedKeyDerivationKey[] = {
    0xdd, 0xe1, 0xca, 0x64, 0xd7, 0xd0, 0x71, 0xf8,
    0x04, 0x86, 0xe5, 0x84, 0x0a, 0xd8, 0xe8, 0xe4,
    0x11, 0x6a, 0x29, 0xec, 0x75, 0x32, 0xdf, 0x7b,
    0x62, 0xaf, 0x55, 0xdc, 0x71, 0xbe, 0x2c, 0x45
  };

  uint16_t len = 32;

  if (keyLens < len) {
    Serial.println("Key release failure");
    exitProgram();
  }

  memcpy(cryptoKeys->authKey, storedAuthenticationKey, 32);
  memcpy(cryptoKeys->keyDerivKey, storedKeyDerivationKey, 32);

  Serial.println("Keys released.");
};
