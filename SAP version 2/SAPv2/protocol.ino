bool performStage1(Stage1Response *stage1Response) {
  Serial.println(F("Starting stage 1"));
  sendStage1Request();
  delay(100);

  // Parse status code and response body
  char responseBody[101] = {0};
  unsigned int bodyLen = 0;
  int statusCode = parseHTTPResponse(responseBody, &bodyLen, 100);

  Serial.print(F("\n\nDisconnecting.\n\n"));
  client.stop(); 
  Serial.print(F("Status Code: ")); Serial.println(statusCode);

  if (statusCode != 201 || bodyLen < 1) {
    return false;
  }

  return parseStage1Json(stage1Response, responseBody);
}

void sendStage1Request() {
  Serial.println(F("Sending stage 1"));

  // Make a HTTP request:
  if (usingFiddler) {
    client.println(F("POST http://www.joekeilty.co.uk/authentication/v2/biometric HTTP/1.1"));
  } else {
    client.println(F("POST /authentication/v2/biometric HTTP/1.1"));
  }

  client.println(F("Host: www.joekeilty.co.uk"));
  client.println(F("Content-Length: 0"));
  client.println(F("Connection: close"));
  client.println();
}

bool parseStage1Json(Stage1Response *stage1Response, char *json) 
{
  delay(100);
  StaticJsonBuffer<100> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(json);
  if (!root.success() || !root.containsKey("session_id") || !root.containsKey("server_id")) {
    Serial.println(F("Malformed payload"));
    return false;
  }

  char session_id_B64[25] = {0}, server_id_B64[25] = {0};
  strncpy(session_id_B64, root.get<const char*>("session_id"), 24);
  strncpy(server_id_B64, root.get<const char*>("server_id"), 24);

  if (strlen(session_id_B64) == 0 || strlen(server_id_B64) == 0) {
    Serial.println(F("Empty payload values"));
    return false;
  }

  int session_idDecLen = base64_dec_len(session_id_B64, strlen(session_id_B64));
  int server_idDecLen = base64_dec_len(server_id_B64, strlen(server_id_B64));
  if (session_idDecLen != 16 || server_idDecLen != 16) {
    Serial.println(F("Invalid payload value lengths"));
    return false;
  }


  char session_id[session_idDecLen+1];
  base64_decode(session_id, session_id_B64, 24);
  char server_id[server_idDecLen+1];
  base64_decode(server_id, server_id_B64, 24);

  // Verify server_id provided is identical. Do this in constant time.
  if (!cryptoSecureCompare(server_id, server_id_stored, 16)) {
    Serial.println(F("Invalid server_id"));
    return false;
  }
  
  // Copy to Stage1Response structure
  memcpy(stage1Response->session_id, session_id, 16);
  memcpy(stage1Response->server_id, server_id, 16);
  
  return true;
}

bool performStage2(Stage1Response *stage1Response, Stage2Request *stage2Request, Stage2Response *stage2Response, uint8_t *authKey) {
  Serial.println(F("Starting stage 2"));
  sendStage2Request(stage1Response, stage2Request, authKey);
  delay(100);

  // Parse status code and response body
  char responseBody[101] = {0};
  unsigned int bodyLen = 0;
  int statusCode = parseHTTPResponse(responseBody, &bodyLen, 100);

  Serial.print(F("\n\nDisconnecting.\n\n"));
  client.stop(); 
  Serial.print(F("Status Code: ")); Serial.println(statusCode);

  if (statusCode != 200 || bodyLen < 1) {
    return false;
  }  

  if (!parseStage2Json(stage2Response, responseBody)) {
    return false;
  }

  // Crypto verify server_mac
  uint8_t calculatedServerMac[16] = {0};
  SHA256 sha256;
  sha256.resetHMAC(authKey, 32);
  sha256.update(stage1Response->server_id, 16);
  sha256.update(stage2Request->client_random, 16);
  sha256.finalizeHMAC(authKey, 32, calculatedServerMac, 16);
  if (!cryptoSecureCompare(calculatedServerMac, stage2Response->server_mac, 16)) {
    Serial.println(F("Invalid server_mac"));
    return false;
  }

  // Truncate expires
  stage2Response->expires = stage2Response->expires > 60 ? 60 : stage2Response->expires;

  return true;
}

void sendStage2Request(Stage1Response *stage1Response, Stage2Request *stage2Request, uint8_t *authKey) {
  SHA256 sha256;
  // Randomly generate client_random
  generateClientRandom(stage2Request);
  // Retrieve client_id
  memcpy(stage2Request->client_id, client_id_stored, 16);
  // Calculate client_mac
  sha256.resetHMAC(authKey, 32);
  sha256.update(stage2Request->client_id, 16);
  sha256.update(stage1Response->server_id, 16);
  sha256.update(stage1Response->session_id, 16);
  sha256.update(stage2Request->client_random, 16);
  sha256.finalizeHMAC(authKey, 32, stage2Request->client_mac, 16);
  printHex(stage2Request->client_id, 16);
  printHex(stage1Response->server_id, 16);
  printHex(stage1Response->session_id, 16);
  printHex(stage2Request->client_random, 16);
  printHex(stage2Request->client_mac, 16);
  printHex(authKey, 32);
  // Construct JSON
  const int BUFFER_SIZE = JSON_OBJECT_SIZE(3);
  StaticJsonBuffer<BUFFER_SIZE> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  // base64 encode fields before adding to JSON object
  char client_randomB64[25], client_idB64[25], client_macB64[25], session_idB64[25];
  base64_encode(client_randomB64, (char *)stage2Request->client_random, 16);
  base64_encode(client_idB64, (char *)stage2Request->client_id, 16);
  base64_encode(client_macB64, (char *)stage2Request->client_mac, 16);
  base64_encode(session_idB64, (char *)stage1Response->session_id, 16);
  // Populate JSON object
  root["client_id"] = client_idB64;
  root["client_random"] = client_randomB64;
  root["client_mac"] = client_macB64;
  int len = root.measureLength();
  // Send request
  if (usingFiddler) {
    client.print(F("POST http://www.joekeilty.co.uk/authentication/v2/biometric/"));
  } else {
    client.print(F("POST /authentication/v2/biometric/"));
  }
  client.print(session_idB64); client.println(F(" HTTP/1.1"));
  client.println(F("Host: www.joekeilty.co.uk"));
  client.println(F("Content-Type: application/json"));
  client.print(F("Content-Length: "));client.println(len);
  client.println(F("Connection: close"));
  client.println();
  root.printTo(client);
}

void generateClientRandom(Stage2Request *stage2Request) {
  uint8_t i;
  for (i=0; i < 16; i++) {
    stage2Request->client_random[i] = Entropy.randomByte();
  }
}

bool parseStage2Json(Stage2Response *stage2Response, char *json) {
  delay(100);
  StaticJsonBuffer<100> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(json);
  if (!root.success() || !root.containsKey("server_mac") || !root.containsKey("expires")) {
    Serial.println(F("Malformed payload"));
    return false;
  }

  char server_mac_B64[25] = {0};
  strncpy(server_mac_B64, root.get<const char*>("server_mac"), 24);

  if (strlen(server_mac_B64) == 0) {
    Serial.println(F("Empty payload values"));
    return false;
  }

  int server_macDecLen = base64_dec_len(server_mac_B64, strlen(server_mac_B64));
  if (server_macDecLen != 16) {
    Serial.println(F("Invalid payload value lengths"));
    return false;
  }

  char server_mac[server_macDecLen+1];
  base64_decode(server_mac, server_mac_B64, 24);

  unsigned int expires = root.get<unsigned int>("expires");
  if (expires < 1) {
    Serial.println(F("Invalid expires field"));
  }
  
  // Copy to Stage2Response structure
  memcpy(stage2Response->server_mac, server_mac, 16);
  stage2Response->expires = expires;
  
  return true;  
}

// Retrieve status code from HTTP response
// Attempt to parse response body up to maxBodyLen into body
int parseHTTPResponse(char *body, unsigned int *bodyLen, unsigned int maxBodyLen) {
  boolean inStatus = false, parsedStatus = false, inBody = false;
  char statusCode[4];
  int statusCodeLen = 0;
  int consecutiveNewLineCount = 0;
  *bodyLen = 0;

  Serial.println(F("Receiving response"));

  while (client.connected()) {
    if (client.available()) {
      char c = client.read();
      Serial.print(c);
      // STATUS CODE PARSING
      if (!parsedStatus) {
        // First space means status code is expected
        if (c == ' ' && !inStatus) {
          inStatus = true;
        // Copy character if we haven't copied 3 yet
        } else if (inStatus && statusCodeLen < 3) {
          statusCode[statusCodeLen] = c;
          statusCodeLen++;
        // End of status code, insert null terminator, stop parsing status code
        } else if (inStatus && statusCodeLen == 3) {
          statusCode[statusCodeLen] = '\0';
          inStatus = false;
          parsedStatus = true;
        }
      }

      if (!inBody) {
        // 2 newlines in a row means we expect the body
        if (c == '\n' && consecutiveNewLineCount == 1) {
          inBody = true;
        // 1 newline in a row means we're at the end of a header
        } else if (c == '\n') {
          consecutiveNewLineCount++;
        // We just had a newline and now are parsing another header
        } else if (c != '\r' && consecutiveNewLineCount > 0) {
          consecutiveNewLineCount--;
        }
      } else {
        if (*bodyLen < maxBodyLen) {
          body[*bodyLen] = c;
          *bodyLen = *bodyLen + 1;          
        }
      }
    
    } 
  }

  return atoi(statusCode);
}



