// UTILITY FUNCTIONS AND COMMON FUNCTIONS

/* Retrieve status code from HTTP response
   Attempt to parse response body up to maxBodyLen into body */
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

/* Emulate exiting of program */
void exitProgram() {
  // Clear up any variables
  while(1);
}

/* Print contents of input in hexadecimal format */
void printHex(uint8_t *input, uint16_t len) {
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
      Serial.println();
    }
 }
}

// See if a and b are identical by comparing size bytes
// Crypto secure as it isn't vulnerable to a timing attack
// SRC: https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time
bool cryptoSecureCompare(const void *a, const void *b, const size_t size) {
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;
 
  for (i = 0; i < size; i++) {
    // Perform XOR of a[i] and b[i]. If different will be 1.
    // Then perform OR of result. If different it will add 1 to result.
    result |= _a[i] ^ _b[i];
  }
 
  return result == 0; 
}
