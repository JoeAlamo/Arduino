#include <ArduinoJson.h>
#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <SPI.h>
#include <Ethernet.h>

void readFingerprint();
int getFingerprintIDez();

// Fingerprint related variables
SoftwareSerial mySerial(2, 3);
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

// Ethernet related variables
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress server(217, 160, 93, 179);
IPAddress ip(192, 168, 0, 177);
EthernetClient client;

// Client related variables
char client_id[] = "dummy";

void setup()  
{
  Serial.begin(9600);

  // set the data rate for the sensor serial port
  finger.begin(57600);
  
  if (finger.verifyPassword()) {
    Serial.println("Found fingerprint sensor!");
  } else {
    Serial.println("Did not find fingerprint sensor :(");
    while (1);
  }

  if (Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    // no point in carrying on, so do nothing forevermore:
    // try to congifure using IP address instead of DHCP:
    Ethernet.begin(mac, ip);
  }

  Serial.println("Ethernet activated."); 
  Serial.println("Place a valid finger to unlock.");
}

void loop()                     // run over and over again
{
  readFingerprint();
  delay(50);
}

void readFingerprint()
{
  // Check fingerprint scanner, get ID if finger present
  int id = -1;
  id = getFingerprintIDez();
  if (id == -1) return;
  // Check if ID is in server's valid list
  performRemoteAuthentication(client_id);
}

bool performRemoteAuthentication(char *client_id) {
  if (!client.connect(server, 80)) {
    Serial.println("Failed to connect");
    return false;
  }
  // Make JSON payload
  StaticJsonBuffer<100> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  root["client_id"] = client_id;
  int len = root.measureLength();

  Serial.println("connected");
  // Make a HTTP request:
  char reqString[50];
  sprintf(reqString, "POST /authentication/biometric/v1 HTTP/1.1");
  client.println(reqString);
  client.println("Host: www.joekeilty.co.uk");
  client.println("Content-Type: application/json");
  client.print("Content-Length: ");client.println(len);
  client.println("Connection: close");
  client.println();
  root.printTo(client);
  delay(100);

  // Just output response for now
  int statusCode = parseHTTPStatusCode();

  Serial.println();
  Serial.println("disconnecting.");
  client.stop(); 

  Serial.print("Status Code: "); Serial.println(statusCode);

  return statusCode == 200;
}

int parseHTTPStatusCode()
{
  boolean inStatus = false;
  char statusCode[4];
  int i = 0;

  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      Serial.print(c);
      if (c == ' ' && !inStatus) {
        inStatus = true;
      }

      if (inStatus && i < 3 && c != ' ') {
        statusCode[i] = c;
        i++;
      }

      if (i == 3) {
        statusCode[i] = '\0';
      }
    }
  }

  return atoi(statusCode);
}

// returns -1 if failed, otherwise returns ID #
int getFingerprintIDez() {
  uint8_t p = finger.getImage();
  if (p != FINGERPRINT_OK)  return -1;

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK)  return -1;

  p = finger.fingerFastSearch();
  if (p != FINGERPRINT_OK)  return -1;
  
  // found a match!
  Serial.print("Found ID #"); Serial.print(finger.fingerID); 
  Serial.print(" with confidence of "); Serial.println(finger.confidence);
  
  return finger.fingerID; 
}


