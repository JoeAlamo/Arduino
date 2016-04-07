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
    client.println(F("POST http://www.joekeilty.co.uk/authentication/v3/biometric HTTP/1.1"));
  } else {
    client.println(F("POST /authentication/v3/biometric HTTP/1.1"));
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

  // Print
  Serial.print(F("\nsession_id:"));
  printHex(stage1Response->session_id, 16);
  Serial.print(F("\nserver_id:"));
  printHex(stage1Response->server_id, 16);
  
  return true;
}
