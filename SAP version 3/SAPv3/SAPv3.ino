#include <Adafruit_Fingerprint.h>
#include <ArduinoJson.h>
#include <Base64.h>
#include <ChaChaPoly.h>
#include <Entropy.h>
#include <Ethernet.h>
#include <SHA256.h>
#include <SoftwareSerial.h>
#include <SPI.h>

// STRUCTURES
typedef struct Stage1Response {
  uint8_t session_id[16];
  uint8_t server_id[16];
} Stage1Response;

typedef struct Stage2Request {
  uint8_t client_id[16];
  uint32_t timestamp;
  uint8_t client_random[16];
  uint8_t client_mac[16];
} Stage2Request;

typedef struct Stage2Response {
  uint8_t server_mac[16];
  unsigned int expires;
} Stage2Response;

typedef struct CryptoKeys {
  uint8_t authKey[32];
  uint8_t keyDerivKey[32];
  uint8_t sessionKey[32];
} CryptoKeys;

// BIOMETRIC VERIFICATION FUNCTION DEFINITIONS
bool currentlyVerified();
bool currentlyBlocked();
bool scanFingerprint();
bool convertFingerprintToTemplate();
bool verifyFingerprint(uint16_t fingerprintID);
void getStoredKeys(CryptoKeys *cryptoKeys, uint16_t keyLens);
void reportFailedVerificationAttempt();
void sendFailedVerificationRequest();
void parseFailedVerificationResponse();
// PROTOCOL FUNCTION DEFINITIONS
bool performRemoteAuthentication(unsigned int *verifiedDuration, CryptoKeys *cryptoKeys);
bool performStage1(Stage1Response *stage1Response);
void sendStage1Request();
bool parseStage1Json(Stage1Response *stage1Response, char *json);
bool performStage2(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, CryptoKeys *cryptoKeys);
void sendStage2Request(Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys);
bool retrieveTimestamp(uint32_t *timestamp);
void generateClientRandom(Stage2Request *stage2Request);
void calculateClientMAC(SHA256 *sha256, Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys);
void generateSessionKey(SHA256 *sha256, Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys);
void encryptAndTag(Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys, char *ciphertextB64, char *tagB64);
bool parseStage2Json(char *ciphertextB64, int *ciphertextB64Len, char *tagB64, char *json);
bool verifyAndDecrypt(Stage1Response *stage1Response, CryptoKeys *cryptoKeys, char *ciphertextB64, int ciphertextB64Len, char *tagB64, char *plaintext, int *plaintextLen);
bool parseDecryptedCiphertext(Stage2Response *stage2Response, char *plaintext, int plaintextLen);
bool verifyServerMAC(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, CryptoKeys *cryptoKeys);
// UTILITY FUNCTION DEFINITIONS
int parseHTTPResponse(char *body, unsigned int *bodyLen, unsigned int maxBodyLen);
void exitProgram();
void printHex(const uint8_t *input, uint16_t len);
bool cryptoSecureCompare(const void *a, const void *b, const size_t size);

// FINGERPRINT SENSOR VARIABLES
SoftwareSerial mySerial(11,12);
Adafruit_Fingerprint fingerprintSensor = Adafruit_Fingerprint(&mySerial);
uint16_t fingerprintID = 1;

// ETHERNET VARIABLES
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xBD };
IPAddress server(217, 160, 93, 179);
IPAddress fiddler(192, 168, 0, 153);
IPAddress ip(192, 168, 0, 120);
EthernetClient client;
bool usingFiddler = false;

// PROTOCOL VARIABLES
const uint8_t client_id_stored[16] = {
  0x6e, 0xf7, 0x33, 0x4e, 0xc4, 0x09, 0x9c, 0x34,
  0xd5, 0x97, 0x73, 0x9e, 0x83, 0x6e, 0xe9, 0xa0
};
const uint8_t server_id_stored[16] = {
  0x04, 0x56, 0x19, 0xe5, 0xc1, 0xad, 0x3b, 0xd4,
  0xac, 0xa8, 0x4c, 0xee, 0x52, 0xb5, 0xae, 0xee
};

unsigned long unixUTCTimestamp = 0;
unsigned long timestampLastRetrievedAt = 0;

unsigned int failedVerificationAttempts = 0;

bool hasBeenVerified = false;
unsigned long verifiedExpiration = 0;
unsigned int verifiedDuration = 0;

// RUN ONCE
void setup() {
  Serial.begin(9600);
  fingerprintSensor.begin(57600);

  Entropy.initialize();

  // Check that fingerprint sensor is connected
  if (fingerprintSensor.verifyPassword()) {
    Serial.println(F("Fingerprint sensor is connected."));
  } else {
    Serial.println(F("Fingerprint sensor is not connected. Reconnect and restart."));
    exitProgram();
  }

  if (usingFiddler) {
    Ethernet.begin(mac, ip);
  } else {
    // Check that we can get Ethernet connection
    if (Ethernet.begin(mac) == 0) {
      Serial.println(F("Failed to configure Ethernet using DHCP"));
      // try to congifure using IP address instead of DHCP:
      Ethernet.begin(mac, ip);
    }    
  }

  Serial.print(F("Ethernet activated - local IP:"));Serial.println(Ethernet.localIP());

  // Retrieve timestamp at start to minimise number of timestamp requests we have to perform across protocol runs
  bool timestampRetrieved = retrieveTimestamp(&unixUTCTimestamp);
  if (timestampRetrieved) {
    timestampLastRetrievedAt = millis() / 1000;
  }
  
  Serial.println(F("Place valid fingerprint when ready."));

  while (1) {
    if (currentlyVerified() || currentlyBlocked()) {
      delay(500);
    } else {
      if (scanFingerprint() && convertFingerprintToTemplate()) {
        if (verifyFingerprint(fingerprintID)) {
          failedVerificationAttempts = 0;
          Serial.println(F("Your fingerprint matched."));
          CryptoKeys cryptoKeys = {
            /* authKey */ {0},
            /* keyDerivKey */ {0},
            /* sessionKey */ {0}
          };
          getStoredKeys(&cryptoKeys, 32);
          Serial.println(F("Beginning SAPv2"));
          hasBeenVerified = performRemoteAuthentication(&verifiedDuration, &cryptoKeys);
          if (hasBeenVerified) {
            verifiedExpiration = millis() + (verifiedDuration * 1000);
            Serial.print(F("Authentication successful. You have "));
            Serial.print(verifiedDuration);
            Serial.println(F(" seconds to log in"));
          } else {
            Serial.println(F("Authentication unsuccessful"));
            delay(2000);
          }
        } else {
          Serial.println(F("Your fingerprint didn't match. Try again."));
          failedVerificationAttempts++;
          if (failedVerificationAttempts == 3) {
            reportFailedVerificationAttempt();
            failedVerificationAttempts = 0;
          }
        }
      } else {
        delay(250);
      }
    }
  }
} 

void loop() {}

bool performRemoteAuthentication(unsigned int *verifiedDuration, CryptoKeys *cryptoKeys) {
  *verifiedDuration = 0;
  if (usingFiddler) {
    if (!client.connect(fiddler, 8888)) {
      Serial.println(F("Failed to connect"));
      return false;
    }
  } else {
    if (!client.connect(server, 80)) {
      Serial.println(F("Failed to connect"));
      return false;
    }
  }

  Serial.println(F("Connected"));

  Stage1Response stage1Response = {
    /* session_id */{0},
    /* server_id */{0}
  };

  if (!performStage1(&stage1Response)) {
    Serial.println(F("Stage 1 failed"));
    return false;
  }

  Stage2Request stage2Request = {
    /* client_id */ {0},
    /* timestamp */ 0,
    /* client_random */ {0},
    /* client_mac */ {0}
  };
  Stage2Response stage2Response = {
    /* server_mac */ {0},
    /* expires */ 0
  };

  if (usingFiddler) {
    if (!client.connect(fiddler, 8888)) {
      Serial.println(F("Failed to connect"));
      return false;
    }
  } else {
    if (!client.connect(server, 80)) {
      Serial.println(F("Failed to connect"));
      return false;
    }
  }

  if (!performStage2(&stage1Response, &stage2Request, &stage2Response, cryptoKeys)) {
    Serial.println(F("Stage 2 failed"));
    return false;
  }

  *verifiedDuration = stage2Response.expires;
  Serial.print(F("Authentication duration (seconds): ")); Serial.println(*verifiedDuration);

  return true;
}



