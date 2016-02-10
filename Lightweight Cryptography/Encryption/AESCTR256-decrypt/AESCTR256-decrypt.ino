#include <AES.h>
#include <CTR.h>

struct DecryptionTest
{
  const char *name;
  byte key[32];
  byte iv[16];
  byte ciphertext[96];
};

static DecryptionTest const AES256CTRTest = {
  "AES-256-CTR-decrypt",
  {0x37, 0x4C, 0x33, 0x53, 0x77, 0x53, 0x71, 0x61,
  0x34, 0x4D, 0x6E, 0x4D, 0x69, 0x50, 0x5A, 0x44,
  0x53, 0x55, 0x46, 0x78, 0x52, 0x79, 0x56, 0x65,
  0x74, 0x6B, 0x41, 0x63, 0x53, 0x47, 0x75, 0x4E},
  {0x50, 0x55, 0x71, 0x78, 0x33, 0x31, 0x7A, 0x36,
   0x53, 0x35, 0x61, 0x65, 0x59, 0x4B, 0x6B, 0x4E},
  {0x81, 0xF9, 0x58, 0xA4, 0xD3, 0x65, 0xAC, 0xCC, 
  0xB9, 0xBE, 0x10, 0x3E, 0x71, 0xD4, 0x94, 0x60, 
  0xD1, 0xCA, 0x81, 0x26, 0xF9, 0xF6, 0xD4, 0x50, 
  0x83, 0xDB, 0xA8, 0xFF, 0xE7, 0x8A, 0x24, 0xC6, 
  0x30, 0xE9, 0xCB, 0x93, 0xB0, 0x30, 0xCA, 0x81, 
  0xC2, 0xD0, 0x26, 0xBC, 0x14, 0x27, 0xDD, 0xF3, 
  0xAC, 0x39, 0x54, 0xF0, 0x81, 0xF3, 0xD7, 0xE0, 
  0xD1, 0xCA, 0xCD, 0xE4, 0x92, 0x41, 0xD0, 0x50, 
  0xEA, 0x96, 0x29, 0x24, 0x22, 0xCB, 0x31, 0xBD, 
  0x34, 0x09, 0x46, 0x91, 0x23, 0x78, 0xD1, 0x4C, 
  0xCC, 0x40, 0x91, 0x84, 0x86, 0x01, 0xA2, 0xED, 
  0xD0, 0xB3, 0xB0, 0x73, 0xBA, 0x31, 0x7E, 0x98
  }
};

CTR<AES256> cipher;

void performDecryption(const struct DecryptionTest *decryption, Cipher *cipher) {
  unsigned long start;
  unsigned long elapsed;
  byte output[96] = {0};

  printHex(decryption->ciphertext, 96);
  Serial.println();
  start = millis();
  cipher->setKey(decryption->key, cipher->keySize());
  cipher->setIV(decryption->iv, cipher->ivSize());
  cipher->decrypt((uint8_t*) output, (uint8_t*)decryption->ciphertext, sizeof(decryption->ciphertext));
  elapsed = millis() - start;
  for (short i=0; i < 96; i++) {
    Serial.print((char)output[i]);
  }
  Serial.println(); Serial.print(elapsed); Serial.print(" milliseconds \n");
}

void printHex(const uint8_t *input, size_t len) {
  for (short i=0; i < len; i++) {
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
    }
 }
}

void setup() {
  Serial.begin(9600);
  Serial.println();
  Serial.print(AES256CTRTest.name);
  Serial.println();
  performDecryption(&AES256CTRTest, &cipher);
}

void loop() {
}