#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>
#include <SPI.h>
#include <Ethernet.h>

void readFingerprint();
int getFingerprintIDez();
void lock();
void unlock();

// Fingerprint related variables
SoftwareSerial mySerial(2, 3);
int unlockPin = 12;
int lockPin = 11;
bool locked = true;
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

// Ethernet related variables
byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress server(217, 160, 93, 179);
IPAddress ip(192, 168, 0, 177);
EthernetClient client;

void setup()  
{
  // Make sure we're locked
  pinMode(unlockPin, OUTPUT);
  pinMode(lockPin, OUTPUT);
  lock();
  
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
  if (!locked) {
    delay(5000);
    lock();
  }
  
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
  if (checkValidFingerprintID(id)) {
    unlock();
  }
}

bool checkValidFingerprintID(int id) {
  if (!client.connect(server, 80)) {
    Serial.println("Failed to connect");
    return false;
  }

  Serial.println("connected");
  // Make a HTTP request:
  char reqString[50];
  sprintf(reqString, "GET /validFingerprint.php?id=%d HTTP/1.1", id);
  client.println(reqString);
  client.println("Host: www.joekeilty.co.uk");
  client.println("Connection: close");
  client.println();
  delay(100);

  // Just output response for now
  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      Serial.print(c);
    }
  }

  Serial.println();
  Serial.println("disconnecting.");
  client.stop(); 

  return true;
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

void lock() {
  Serial.print("Locking...\n");
  digitalWrite(lockPin, HIGH);
  digitalWrite(unlockPin, LOW);
  locked = true;
}

void unlock() {
  Serial.print("Unlocking...\n");
  digitalWrite(lockPin, LOW);
  digitalWrite(unlockPin, HIGH);
  locked = false;
}

