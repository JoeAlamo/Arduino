#include <Adafruit_Fingerprint.h>
#include <ArduinoJson.h>
#include <Base64.h>
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
  uint8_t client_random[16];
  uint8_t client_mac[16];
} Stage2Request;

typedef struct Stage2Response {
  uint8_t server_mac[16];
  unsigned int expires;
} Stage2Response;

// BIOMETRIC VERIFICATION FUNCTION DEFINITIONS
bool currentlyVerified();
bool currentlyBlocked();
bool scanFingerprint();
bool convertFingerprintToTemplate();
bool verifyFingerprint(uint16_t fingerprintID);
void getStoredAuthenticationKey(uint8_t *akBuf, uint16_t akBufSize);
// PROTOCOL FUNCTION DEFINITIONS
bool performRemoteAuthentication(unsigned int *verifiedDuration, uint8_t *authKey);
bool performStage1(Stage1Response *stage1Response);
void sendStage1Request();
bool parseStage1Json(Stage1Response *stage1Response, char *json);
bool performStage2(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, uint8_t *authKey);
void sendStage2Request(Stage1Response *stage1Response, Stage2Request *stage2Request, uint8_t *authKey);
void generateClientRandom(Stage2Request *stage2Request);
bool parseStage2Json(Stage2Response *stage2Response, char *json);
int parseHTTPResponse(char *body, unsigned int *bodyLen, unsigned int maxBodyLen);
// UTILITY FUNCTION DEFINITIONS
void exitProgram();
void printHex(const uint8_t *input, uint16_t len);

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

bool hasBeenVerified = false;
unsigned long verifiedExpiration = 0;
unsigned int verifiedDuration = 0;

// RUN ONCE
void setup() {
  Serial.begin(9600);
  fingerprintSensor.begin(57600);

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
  Serial.println(F("Place valid fingerprint when ready."));

  while (1) {
    if (currentlyVerified() || currentlyBlocked()) {
      delay(500);
    } else {
      if (scanFingerprint() && convertFingerprintToTemplate()) {
        if (verifyFingerprint(fingerprintID)) {
          Serial.println(F("Your fingerprint matched."));
          uint8_t authenticationKey[32] = {0};
          getStoredAuthenticationKey(authenticationKey, 32);
          Serial.println(F("Beginning SAPv2"));
          hasBeenVerified = performRemoteAuthentication(&verifiedDuration, authenticationKey);
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
        }
      } else {
        delay(50);
      }
    }
  }
} 

void loop() {}

// SAPv1 FUNCTIONS

bool performRemoteAuthentication(unsigned int *verifiedDuration, uint8_t *authKey) {
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

  printHex(stage1Response.session_id, 16);
  printHex(stage1Response.server_id, 16);

  Stage2Request stage2Request = {
    /* client_id */ {0},
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

  if (!performStage2(&stage1Response, &stage2Request, &stage2Response, authKey)) {
    Serial.println(F("Stage 2 failed"));
    return false;
  }
  // If 200 then payload with session_id and server_id should be present
//  if (statusCode == 200 && bodyLen > 0) {
//    // Parse session_id and server_id
//    bool successfulParse = parseExpiresJson(verifiedDuration, responseBody);
//    if (successfulParse && *verifiedDuration > 0) {
//      *verifiedDuration = *verifiedDuration > 60 ? 60 : *verifiedDuration;
//      Serial.print(F("Authentication duration (seconds): ")); Serial.println(*verifiedDuration);
//
//      return true;
//    }
//  }

  return false;
}



