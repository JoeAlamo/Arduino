bool performStage2(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, CryptoKeys *cryptoKeys) {
  Serial.println(F("Starting stage 2"));
  sendStage2Request(stage1Response, stage2Request, cryptoKeys);
  delay(100);

  // Parse status code and response body
  char responseBody[151] = {0};
  unsigned int bodyLen = 0;
  int statusCode = parseHTTPResponse(responseBody, &bodyLen, 150);

  Serial.print(F("\n\nDisconnecting.\n\n"));
  client.stop(); 
  Serial.print(F("Status Code: ")); Serial.println(statusCode);

  if (statusCode != 200 || bodyLen < 1) {
    // May be due to invalid timestamp - lets update
    retrieveTimestamp(&unixUTCTimestamp);
    return false;
  }  

  char ciphertextB64[80] = {0}, tagB64[25];
  int ciphertextB64Len = 0;

  if (!parseStage2Json(ciphertextB64, &ciphertextB64Len, tagB64, responseBody)) {
    return false;
  }

  char plaintext[80] = {0};
  int plaintextLen = 0;
  if (!verifyAndDecrypt(stage1Response, cryptoKeys, ciphertextB64, ciphertextB64Len, tagB64, plaintext, &plaintextLen)) {
    return false;
  }

  // Should result in JSON object containing server_mac and expires - lets parse it
  if (!parseDecryptedCiphertext(stage2Response, plaintext, plaintextLen)) {
    return false;
  }

  // Crypto verify server_mac
  if (!verifyServerMAC(stage1Response, stage2Request, stage2Response, cryptoKeys)) {
    return false;
  }

  // Truncate expires
  stage2Response->expires = stage2Response->expires > 60 ? 60 : stage2Response->expires;

  return true;
}

void sendStage2Request(Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys) {
  // Retrieve timestamp
  if (timestampLastRetrievedAt > 0) {
    // If we've previously retrieved the timestamp, lets update it based on the program timer
    // This is better than having to retrieve it again
    stage2Request->timestamp = unixUTCTimestamp + ((millis() / 1000) - timestampLastRetrievedAt);
  } else {
    Serial.println(F("Retrieving timestamp"));
    bool retrievedTimestamp = retrieveTimestamp(&unixUTCTimestamp);
    if (retrievedTimestamp) {
      timestampLastRetrievedAt = millis() / 1000;
      stage2Request->timestamp = unixUTCTimestamp;
    } else {
      Serial.println(F("Failed to retrieve timestamp. Restart device."));
      exitProgram();      
    }
  }

  Serial.print(F("Timestamp:"));
  Serial.println(stage2Request->timestamp);

  // Randomly generate client_random
  generateClientRandom(stage2Request);
  // Retrieve client_id
  memcpy(stage2Request->client_id, client_id_stored, 16);
  
  SHA256 sha256;
  // Calculate client_mac
  calculateClientMAC(&sha256, stage1Response, stage2Request, cryptoKeys);
  // Generate session key
  generateSessionKey(&sha256, stage1Response, stage2Request, cryptoKeys);
  // Encrypt and tag
  char ciphertextB64[150] = {0}, tagB64[25];
  int ciphertextB64Len = 0;
  encryptAndTag(stage1Response, stage2Request, cryptoKeys, ciphertextB64, tagB64);

  // Construct JSON
  const int BUFFER_SIZE = JSON_OBJECT_SIZE(4);
  StaticJsonBuffer<BUFFER_SIZE> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  // base64 encode client_id & session_id
  char client_idB64[25], session_idB64[25];
  base64_encode(client_idB64, (char *)stage2Request->client_id, 16);
  base64_encode(session_idB64, (char *)stage1Response->session_id, 16);

  // Populate JSON object
  root["client_id"] = client_idB64;
  root["timestamp"] = stage2Request->timestamp;
  root["ciphertext"] = ciphertextB64;
  root["tag"] = tagB64;
  int len = root.measureLength();
  // Send request
  if (usingFiddler) {
    client.print(F("POST http://www.joekeilty.co.uk/authentication/v3/biometric/"));
  } else {
    client.print(F("POST /authentication/v3/biometric/"));
  }
  client.print(session_idB64); client.println(F(" HTTP/1.1"));
  client.println(F("Host: www.joekeilty.co.uk"));
  client.println(F("Content-Type: application/json"));
  client.print(F("Content-Length: "));client.println(len);
  client.println(F("Connection: close"));
  client.println();
  root.printTo(client);
}

bool retrieveTimestamp(uint32_t *timestamp) {
  /* Taken from https://www.arduino.cc/en/Tutorial/UdpNtpClient and modified */
  unsigned int localPort = 8888;       // local port to listen for UDP packets
  char timeServer[] = "time.nist.gov"; // time.nist.gov NTP server(s) - round robin
  const int NTP_PACKET_SIZE = 48; // NTP time stamp is in the first 48 bytes of the message
  byte packetBuffer[NTP_PACKET_SIZE] = {0}; //buffer to hold incoming and outgoing packets
  EthernetUDP Udp;
  Udp.begin(localPort);

  int tsFailCount = 0;

  while (!sendAndReceiveNTPPacket(&Udp, timestamp) && tsFailCount < 30) {
    tsFailCount++;
  }

  Udp.stop();

  return tsFailCount != 10;
}

bool sendAndReceiveNTPPacket(EthernetUDP *Udp, uint32_t *timestamp) {
  /* Taken from https://www.arduino.cc/en/Tutorial/UdpNtpClient and modified */
  char timeServer[] = "time.nist.gov"; // time.nist.gov NTP server(s) - round robin
  const int NTP_PACKET_SIZE = 48; // NTP time stamp is in the first 48 bytes of the message
  byte packetBuffer[NTP_PACKET_SIZE] = {0}; //buffer to hold incoming and outgoing packets

  // Initialize values needed to form NTP request
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 16;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
//  packetBuffer[12]  = 49;
//  packetBuffer[13]  = 0x4E;
//  packetBuffer[14]  = 49;
//  packetBuffer[15]  = 52;

  // send a packet requesting a timestamp:
  Udp->beginPacket(timeServer, 123); //NTP requests are to port 123
  Udp->write(packetBuffer, NTP_PACKET_SIZE);
  Udp->endPacket();

  delay(2000);
  if (Udp->parsePacket()) {
    Udp->read(packetBuffer, NTP_PACKET_SIZE); 
    // the timestamp starts at byte 40 of the received packet and is four bytes,
    // or two words, long. First, extract the two words:
    unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
    unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
    // combine the four bytes (two words) into a long integer, NTP time (sec since Jan 1 1900)
    unsigned long secsSince1900 = highWord << 16 | lowWord;
    // Conver to Unix time (starts 70 years later):
    const unsigned long seventyYears = 2208988800UL;
    // subtract seventy years:
    *timestamp = secsSince1900 - seventyYears;
    // print Unix time:
    Serial.print("Timestamp:");
    Serial.println(*timestamp);
    
    return true;
  } else {
    return false;
  }  
}

void generateClientRandom(Stage2Request *stage2Request) {
  uint8_t i;
  for (i=0; i < 16; i++) {
    stage2Request->client_random[i] = Entropy.randomByte();
  }
}

void calculateClientMAC(SHA256 *sha256, Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys) {
  // client_mac is HMAC-SHA256 of client_id||server_id||session_id||client_random
  sha256->resetHMAC(cryptoKeys->authKey, 32);
  sha256->update(stage2Request->client_id, 16);
  sha256->update(stage1Response->server_id, 16);
  sha256->update(stage1Response->session_id, 16);
  sha256->update(stage2Request->client_random, 16);
  sha256->finalizeHMAC(cryptoKeys->authKey, 32, stage2Request->client_mac, 16);
  Serial.print(F("\nclient_id:"));
  printHex(stage2Request->client_id, 16);
  Serial.print(F("\nclient_random:"));
  printHex(stage2Request->client_random, 16);
  Serial.print(F("\nauthentication key:"));
  printHex(cryptoKeys->authKey, 32);
  Serial.print(F("\nclient_mac:"));
  printHex(stage2Request->client_mac, 16);  
}

void generateSessionKey(SHA256 *sha256, Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys) {
  uint8_t salt[20] = {0},
          prk[32] = {0},
          iterations = 1;
  memcpy(salt, &stage2Request->timestamp, 4);
  memcpy(salt+4, stage1Response->session_id, 16);
  // Step 1: Extract PRK using KDK as IKM and timestamp||session_id as the salt
  Serial.print(F("\nKDK:"));
  printHex(cryptoKeys->keyDerivKey, 32);
  sha256->resetHMAC(salt, 20);
  sha256->update(cryptoKeys->keyDerivKey, 32);
  sha256->finalizeHMAC(salt, 20, prk, 32);
  Serial.print(F("\nPRK:"));
  printHex(prk, 32);
  // Step 2: Expand PRK using client_id||server_id as context, and PRK as the key.
  // As we only need a 32 byte session key, we just have to perform one iteration
  sha256->resetHMAC(prk, 32);
  sha256->update(stage2Request->client_id, 16);
  sha256->update(stage1Response->server_id, 16);
  sha256->update(&iterations, 1);
  sha256->finalizeHMAC(prk, 32, cryptoKeys->sessionKey, 32);
  Serial.print(F("\nSession key:"));
  printHex(cryptoKeys->sessionKey, 32);
}

void encryptAndTag(Stage1Response *stage1Response, Stage2Request *stage2Request, CryptoKeys *cryptoKeys, char *ciphertextB64, char *tagB64) {
  // Create JSON object containing client_randomB64 and client_macB64
  const int BUFFER_SIZE = JSON_OBJECT_SIZE(2);
  StaticJsonBuffer<BUFFER_SIZE> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  // base64 encode fields before adding to JSON object
  char client_randomB64[25], client_macB64[25], rawJson[100] = {0};
  base64_encode(client_randomB64, (char *)stage2Request->client_random, 16);
  base64_encode(client_macB64, (char *)stage2Request->client_mac, 16);
  // Populate JSON object
  root["client_random"] = client_randomB64;
  root["client_mac"] = client_macB64;
  int jsonLen = root.measureLength();
  root.printTo(rawJson, 100);
  Serial.println(rawJson);
  // Encrypt & tag using session key and nonce val of 0, with session_id as AAD
  uint8_t nonce[12] = {0}, ciphertext[jsonLen], tag[16];
  Serial.print(F("\nnonce:"));
  printHex(nonce, 12);
  Serial.print(F("\nsession_id:"));
  printHex(stage1Response->session_id, 16);
  ChaChaPoly aeadCipher;
  aeadCipher.clear();
  aeadCipher.setKey(cryptoKeys->sessionKey, 32);
  aeadCipher.setIV(nonce, 12);
  aeadCipher.addAuthData(stage1Response->session_id, 16);
  aeadCipher.encrypt(ciphertext, (uint8_t *) rawJson, jsonLen);
  Serial.print(F("\nciphertext:"));
  printHex(ciphertext, jsonLen);
  aeadCipher.computeTag(tag, 16);
  Serial.print(F("\ntag:"));
  printHex(tag, 16);
  // Base64 encode ciphertext and the tag
  base64_encode(ciphertextB64, (char *)ciphertext, jsonLen);
  base64_encode(tagB64, (char *)tag, 16);
}

bool parseStage2Json(char *ciphertextB64, int *ciphertextB64Len, char *tagB64, char *json) {
  delay(100);
  StaticJsonBuffer<150> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(json);
  if (!root.success() || !root.containsKey("ciphertext") || !root.containsKey("tag")) {
    Serial.println(F("Malformed payload - ciphertext / tag"));
    return false;
  }

  strncpy(ciphertextB64, root.get<const char*>("ciphertext"), 79);
  strncpy(tagB64, root.get<const char*>("tag"), 24);

  if (strlen(ciphertextB64) == 0 || strlen(tagB64) == 0) {
    Serial.println(F("Invalid payload lengths"));
    return false;
  }
  *ciphertextB64Len = strlen(ciphertextB64);

  return true;
}

bool verifyAndDecrypt(Stage1Response *stage1Response, CryptoKeys *cryptoKeys, char *ciphertextB64, int ciphertextB64Len, char *tagB64, char *plaintext, int *plaintextLen) {
  // Base 64 decode the ciphertext and tag
  int ciphertextDecLen = base64_dec_len(ciphertextB64, ciphertextB64Len);
  int tagDecLen = base64_dec_len(tagB64, strlen(tagB64));
  if (tagDecLen != 16 || ciphertextDecLen > 80) {
    Serial.println(F("Invalid payload value lengths"));
    return false;
  }

  char ciphertext[ciphertextDecLen+1];
  base64_decode(ciphertext, ciphertextB64, ciphertextB64Len);
  char tag[tagDecLen+1];
  base64_decode(tag, tagB64, strlen(tagB64));

  Serial.print(F("\nciphertext raw:\n"));
  printHex((uint8_t *)ciphertext, ciphertextDecLen);
  Serial.print(F("\ntag raw:\n"));
  printHex((uint8_t *)tag, tagDecLen);
  
  // Verify the tag by authenticating the ciphertext + session_id. This library requires decrypting before verification
  uint8_t nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
  };
  Serial.print(F("\nnonce:\n"));
  printHex(nonce, 12);
  
  ChaChaPoly aeadCipher;
  aeadCipher.clear();
  aeadCipher.setKey(cryptoKeys->sessionKey, 32);
  aeadCipher.setIV(nonce, 12);
  aeadCipher.addAuthData(stage1Response->session_id, 16);
  aeadCipher.decrypt((uint8_t *)plaintext, (uint8_t *)ciphertext, ciphertextDecLen);
  if (!aeadCipher.checkTag(tag, tagDecLen)) {
    Serial.println(F("Invalid tag"));
    return false;
  }

  Serial.print(F("\nplaintext json:\n"));
  Serial.println(plaintext);

  *plaintextLen = ciphertextDecLen;

  return true;
}

bool parseDecryptedCiphertext(Stage2Response *stage2Response, char *plaintext, int plaintextLen) {
  // Plaintext should be a json object containing server_mac (B64) and expires
  StaticJsonBuffer<80> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(plaintext);
  if (!root.success() || !root.containsKey("server_mac") || !root.containsKey("expires")) {
    Serial.println(F("Malformed payload - server_mac / expires"));
    return false;
  }

  // Extract, verify, base64decode server_mac
  char server_macB64[25] = {0};
  strncpy(server_macB64, root.get<const char*>("server_mac"), 24);

  if (strlen(server_macB64) == 0) {
    Serial.println(F("Empty payload values"));
    return false;
  }

  int server_macB64DecLen = base64_dec_len(server_macB64, strlen(server_macB64));
  if (server_macB64DecLen != 16) {
    Serial.println(F("Invalid payload length - server_mac"));
    return false;
  }
  char server_mac[server_macB64DecLen+1];
  base64_decode(server_mac, server_macB64, strlen(server_macB64));

  // Extract, verify expires
  unsigned int expires = root.get<unsigned int>("expires");
  if (expires < 1) {
    Serial.println(F("Invalid expires field"));
    return false;
  }

  // Copy out
  memcpy(stage2Response->server_mac, server_mac, 16);
  stage2Response->expires = expires;

  Serial.print(F("\nReceived server_mac:\n"));
  printHex(stage2Response->server_mac, 16);

  return true;
}

bool verifyServerMAC(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, CryptoKeys *cryptoKeys) {
  uint8_t calculatedServerMac[16] = {0};
  SHA256 sha256;
  sha256.resetHMAC(cryptoKeys->authKey, 32);
  sha256.update(stage1Response->server_id, 16);
  sha256.update(stage2Request->client_random, 16);
  sha256.finalizeHMAC(cryptoKeys->authKey, 32, calculatedServerMac, 16);
  Serial.print(F("\nCalculated server_mac:"));
  printHex(calculatedServerMac, 16);
  if (!cryptoSecureCompare(calculatedServerMac, stage2Response->server_mac, 16)) {
    Serial.println(F("Invalid server_mac"));
    return false;
  }

  return true;
}

