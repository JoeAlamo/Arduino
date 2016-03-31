#include <Adafruit_Fingerprint.h>
#include <ArduinoJson.h>
#include <Ethernet.h>
#include <SoftwareSerial.h>
#include <SPI.h>

// FUNCTION DEFINITIONS
bool currentlyVerified();
bool currentlyBlocked();
bool scanFingerprint();
bool convertFingerprintToTemplate();
bool verifyFingerprint(uint16_t fingerprintID);
void getStoredAuthenticationKey(uint8_t *akBuf, uint16_t akBufSize);
bool performRemoteAuthentication(unsigned int *verifiedDuration);
int parseHTTPResponse(char *body, unsigned int *bodyLen, unsigned int maxBodyLen);
bool parseExpiresJson(unsigned int *expires, char *json);
void exitProgram();
void printHex(const uint8_t *input, uint16_t len);

// FINGERPRINT SENSOR VARIABLES
SoftwareSerial mySerial(2,3);
Adafruit_Fingerprint fingerprintSensor = Adafruit_Fingerprint(&mySerial);
uint16_t fingerprintID = 1;

// ETHERNET VARIABLES
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress server(217, 160, 93, 179);
IPAddress ip(192, 168, 0, 50);
EthernetClient client;

// PROTOCOL VARIABLES
const char client_id[] = "bvczTsQJnDTVl3Oeg27poA==";
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

  // Check that we can get Ethernet connection
  if (Ethernet.begin(mac) == 0) {
    Serial.println(F("Failed to configure Ethernet using DHCP"));
    // try to congifure using IP address instead of DHCP:
    Ethernet.begin(mac, ip);
  }

  Serial.println(F("Ethernet activated"));
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
          Serial.println(F("Beginning SAPv1"));
          hasBeenVerified = performRemoteAuthentication(&verifiedDuration);
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

bool performRemoteAuthentication(unsigned int *verifiedDuration) {
  *verifiedDuration = 0;
  if (!client.connect(server, 80)) {
    Serial.println(F("Failed to connect"));
    return false;
  }
  Serial.println(F("Connected"));

  sendRequest();
  delay(100);

  // Parse status code and response body
  char responseBody[101] = {0};
  unsigned int bodyLen = 0;
  int statusCode = parseHTTPResponse(responseBody, &bodyLen, 100);

  Serial.print(F("\n\nDisconnecting.\n\n"));
  client.stop(); 
  Serial.print(F("Status Code: ")); Serial.println(statusCode);

  // If 200 then payload with expires should be present
  if (statusCode == 200 && bodyLen > 0) {
    // Parse expires
    bool successfulParse = parseExpiresJson(verifiedDuration, responseBody);
    if (successfulParse && *verifiedDuration > 0) {
      Serial.print(F("Authentication duration (seconds): ")); Serial.println(*verifiedDuration);

      return true;
    }
  }

  return false;
}

void sendRequest() {
  Serial.println(F("Sending request"));
  // Make JSON payload
  StaticJsonBuffer<100> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  root["client_id"] = client_id;
  int len = root.measureLength();

  // Make a HTTP request:
  client.println(F("POST /authentication/v1/biometric HTTP/1.1"));
  client.println(F("Host: www.joekeilty.co.uk"));
  client.println(F("Content-Type: application/json"));
  client.print(F("Content-Length: "));client.println(len);
  client.println(F("Connection: close"));
  client.println();
  root.printTo(client);
}

// Retrieve status code from HTTP response
// Attempt to parse response body up to maxBodyLen into body
int parseHTTPResponse(char *body, unsigned int *bodyLen, unsigned int maxBodyLen) {
  boolean inStatus = false, inBody = false;
  char statusCode[4];
  int statusCodeLen = 0;
  int newLineCount = 0;
  *bodyLen = 0;

  Serial.println(F("Receiving response"));

  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      Serial.print(c);
      // STATUS CODE PARSING
      if (c == ' ' && !inStatus) {
        inStatus = true;
      }

      if (inStatus && statusCodeLen < 3 && c != ' ') {
        statusCode[statusCodeLen] = c;
        statusCodeLen++;
      }

      if (statusCodeLen == 3) {
        statusCode[statusCodeLen] = '\0';
      }
      
      // DETECT IF IN BODY (response body is separated from headers by 2 NL)
      if (c == '\n' && newLineCount == 1) {
        inBody = true;
      }

      // Increment newline count if not already in response body
      // This means we are at the end of a header
      if (c == '\n' && !inBody) {
        newLineCount++;
      }

      // We have just started parsing another header, decrease new line count
      if (c != '\n' && c != '\r' && newLineCount > 0 && !inBody) {
        newLineCount--;
      }

      // If we are in response body, keep parsing body until maxBodyLen is reached
      if (inBody && *bodyLen < maxBodyLen) {
        body[*bodyLen] = c;
        *bodyLen = *bodyLen + 1;
      }
    } 
  }

  return atoi(statusCode);
}

bool parseExpiresJson(unsigned int *expires, char *json) 
{
  StaticJsonBuffer<100> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(json);
  if (root.success() && root.containsKey("expires")) {
    *expires = root.get<unsigned int>("expires");

    return true;
  } else {
    return false;
  }
}

// UTILITY FUNCTIONS 
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


