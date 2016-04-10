void reportFailedVerificationAttempt() {
  // Construct request
  Serial.println(F("3 failed verification attempts in a row have been detected."));
  Serial.println(F("Reporting the failed verification attempts."));

  if (usingFiddler) {
    if (!client.connect(fiddler, 8888)) {
      Serial.println(F("Failed to connect"));
      return;
    }
  } else {
    if (!client.connect(server, 80)) {
      Serial.println(F("Failed to connect"));
      return;
    }
  }
  
  sendFailedVerificationRequest();
  
  // Parse response
  parseFailedVerificationResponse();

  client.stop();
}

void sendFailedVerificationRequest() {
  const int BUFFER_SIZE = JSON_OBJECT_SIZE(1);
  StaticJsonBuffer<BUFFER_SIZE> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  // base64 encode client_id
  char client_idB64[25];
  base64_encode(client_idB64, (char *)client_id_stored, 16);

  // Populate JSON object
  root["client_id"] = client_idB64;
  int len = root.measureLength();

  Serial.println(F("Connected"));

  // Send request
  if (usingFiddler) {
    client.println(F("POST http://www.joekeilty.co.uk/authentication/failed-verification HTTP/1.1"));
  } else {
    client.println(F("POST /authentication/failed-verification HTTP/1.1"));
  }
  client.println(F("Host: www.joekeilty.co.uk"));
  client.println(F("Content-Type: application/json"));
  client.print(F("Content-Length: "));client.println(len);
  client.println(F("Connection: close"));
  client.println();
  root.printTo(client);  
}

void parseFailedVerificationResponse() {
    // Parse status code
  char responseBody[1] = {0};
  unsigned int bodyLen = 0;
  int statusCode = parseHTTPResponse(responseBody, &bodyLen, 0);

  Serial.print(F("\n\nDisconnecting.\n\n"));
  client.stop(); 
  Serial.print(F("Status Code: ")); Serial.println(statusCode);

  if (statusCode == 201) {
    Serial.println(F("Failed verification attempt reported successfully"));
  } else {
    Serial.println(F("A problem occurred when reporting the failed verification attempt"));
  }
}

