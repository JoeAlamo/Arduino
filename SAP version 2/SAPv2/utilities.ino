// UTILITY FUNCTIONS AND COMMON FUNCTIONS

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
