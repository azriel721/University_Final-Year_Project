#include <ELECHOUSE_CC1101_SRC_DRV.h>
#include <SPI.h>
#include <EEPROM.h>
#include <Crypto.h>
#include <AES.h>
#include <SHA256.h>
#include <string.h>

// ================= CONFIG =================
// Actions
#define ACTION_UNLOCK 0
#define ACTION_LOCK   1

// LEDs
#define LED_GREEN D0   // GPIO16
#define LED_RED   D8   // GPIO15

// EEPROM
#define EEPROM_ADDR 0
#define EEPROM_SAVE_INTERVAL 10  // Save every 10 updates
#define ROLLING_WINDOW 256       // Number of codes to check ahead

static const uint32_t CAR_ID    = 0xCAFEBABE;
static const uint32_t KEYFOB_ID = 0x12345678;

static const uint8_t  ROLLING_KEY[16] = {
  0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
  0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

static const uint8_t  TOTP_SECRET[32] = {
  0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x12,0x34,
  0x56,0x78,0x9A,0xBC,0xDE,0xAD,0xBE,0xEF,
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
};

// Packet structure
struct Packet {
  uint32_t carID;
  uint32_t keyfobID;
  uint8_t  action;
  uint32_t rollingCode;
  uint32_t totp;
};

uint32_t lastRollingCounter = 0;
uint32_t lastSavedCounter = 0;

// Pre-initialized crypto objects to avoid overhead
AES128 aes;
SHA256 sha256;

// defining PINs set for ESP8266 - WEMOS D1 MINI module
byte sck = 14;   // D5
byte miso = 12;  // D6
byte mosi = 13;  // D7
byte ss = 15;    // D8
int gdo0 = 5;    // D1
int gdo2 = 4;    // D2

// ============= CC1101 INIT =============
void cc1101initialize(void) {
  ELECHOUSE_cc1101.setSpiPin(sck, miso, mosi, ss);
  ELECHOUSE_cc1101.setGDO(gdo0, gdo2);
  ELECHOUSE_cc1101.Init();

  ELECHOUSE_cc1101.setCCMode(1);
  ELECHOUSE_cc1101.setModulation(2);
  ELECHOUSE_cc1101.setMHZ(433.92);
  ELECHOUSE_cc1101.setPA(10);
  ELECHOUSE_cc1101.setSyncMode(2);
  ELECHOUSE_cc1101.setSyncWord(211, 145);
  ELECHOUSE_cc1101.setPktFormat(0);
  ELECHOUSE_cc1101.setCrc(0);
  ELECHOUSE_cc1101.setLengthConfig(1);
  ELECHOUSE_cc1101.setWhiteData(0);
  ELECHOUSE_cc1101.setAdrChk(0);
  ELECHOUSE_cc1101.setDRate(9.6);
  ELECHOUSE_cc1101.setRxBW(812.50);
}

// ============= CRYPTO FUNCTIONS =============
uint32_t generateRollingCode(uint32_t counter) {
  yield(); // Feed watchdog before crypto
  
  aes.setKey(ROLLING_KEY, 16);
  yield(); // Feed after setKey
  
  uint8_t input[16] = {0};
  memcpy(input, &counter, sizeof(counter));
  
  uint8_t out[16];
  aes.encryptBlock(out, input);
  
  yield(); // Feed after encryption
  
  return *(uint32_t*)out;
}

uint32_t generateTOTP(uint32_t epoch) {
  yield(); // Feed watchdog before crypto
  
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = epoch & 0xFF;
    epoch >>= 8;
  }

  uint8_t hash[32];
  sha256.resetHMAC(TOTP_SECRET, sizeof(TOTP_SECRET));
  yield(); // Feed after reset
  
  sha256.update(msg, sizeof(msg));
  yield(); // Feed after update
  
  sha256.finalizeHMAC(TOTP_SECRET, sizeof(TOTP_SECRET), hash, sizeof(hash));
  yield(); // Feed after finalize

  int offset = hash[31] & 0x0F;
  uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset+1] & 0xFF) << 16) |
                    ((hash[offset+2] & 0xFF) << 8) |
                    (hash[offset+3] & 0xFF);
  return binary % 1000000;
}

// ============= VALIDATION =============
bool validatePacket(Packet &pkt) {
  yield(); // Feed watchdog at start
  
  // Basic ID check
  if (pkt.carID != CAR_ID || pkt.keyfobID != KEYFOB_ID) {
    Serial.println("Invalid ID");
    return false;
  }

  Serial.printf("Validating: RC=%lu, TOTP=%lu, LastCounter=%lu\n", 
                pkt.rollingCode, pkt.totp, lastRollingCounter);
  
  // Check rolling code window (256 codes ahead)
  // Use a regular counter to prevent overflow issues
  for (uint16_t offset = 0; offset < ROLLING_WINDOW; offset++) {
    yield(); // CRITICAL: Feed watchdog in loop
    
    uint32_t testCounter = lastRollingCounter + offset;
    
    if (pkt.rollingCode == generateRollingCode(testCounter)) {
      Serial.printf("Rolling code valid (counter=%lu)\n", testCounter);
      lastRollingCounter = testCounter + 1;
      
      // Save counter periodically to reduce EEPROM wear
      if (lastRollingCounter - lastSavedCounter >= EEPROM_SAVE_INTERVAL) {
        EEPROM.put(EEPROM_ADDR, lastRollingCounter);
        EEPROM.commit();
        lastSavedCounter = lastRollingCounter;
        Serial.printf("Counter saved: %lu\n", lastRollingCounter);
      }

      yield(); // Feed before TOTP generation
      
      // Validate TOTP (check current and previous 30-second window)
      uint32_t currentEpoch = (millis() / 1000) / 30;
      uint32_t currentTOTP = generateTOTP(currentEpoch);
      
      if (pkt.totp == currentTOTP) {
        Serial.println("TOTP valid (current window)!");
        return true;
      }
      
      yield();
      
      // Check previous window in case of timing issues
      uint32_t prevTOTP = generateTOTP(currentEpoch - 1);
      if (pkt.totp == prevTOTP) {
        Serial.println("TOTP valid (previous window)!");
        return true;
      }

      // TOTP mismatch - send sync
      Serial.printf("TOTP mismatch! Expected=%lu or %lu, Got=%lu\n", 
                    currentTOTP, prevTOTP, pkt.totp);
      
      yield();
      noInterrupts();
      ELECHOUSE_cc1101.SetTx();
      interrupts();
      
      delay(50);
      yield();
      
      int32_t timeOffset = 0; // Time offset to send back
      ELECHOUSE_cc1101.SendData((uint8_t*)&timeOffset, sizeof(timeOffset));
      
      delay(100); // Give more time for transmission
      yield();
      
      noInterrupts();
      ELECHOUSE_cc1101.SetRx();
      interrupts();
      
      delay(50);
      Serial.println("Sync sent");
      
      return false;
    }
    
    // Yield every 8 iterations to prevent WDT timeout
    if (offset % 8 == 0) {
      yield();
    }
  }
  
  Serial.println("Rolling code not in window");
  return false;
}

// ============= ACTIONS =============
void lockCar() {
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED, HIGH);
  Serial.println("\n>>> CAR LOCKED <<<\n");
}

void unlockCar() {
  digitalWrite(LED_RED, LOW);
  digitalWrite(LED_GREEN, HIGH);
  Serial.println("\n>>> CAR UNLOCKED <<<\n");
}

// ============= SETUP & LOOP =============
void setup() {
  // Disable watchdog immediately
  ESP.wdtDisable();
  
  Serial.begin(115200);
  delay(200);
  
  Serial.println("\n\n=== Car Receiver Starting ===");
  
  EEPROM.begin(512);
  yield();

  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  yield();

  lockCar(); // Default to locked state
  
  EEPROM.get(EEPROM_ADDR, lastRollingCounter);
  
  // Check for corrupted/invalid counter value
  if (lastRollingCounter == 0xFFFFFFFF || lastRollingCounter > 0xFFFFFF00) {
    Serial.println("WARNING: Counter corrupted or near overflow, resetting to 0");
    lastRollingCounter = 0;
    EEPROM.put(EEPROM_ADDR, lastRollingCounter);
    EEPROM.commit();
  }
  
  lastSavedCounter = lastRollingCounter;
  Serial.printf("Last rolling counter: %lu\n", lastRollingCounter);
  yield();

  Serial.println("Initializing CC1101...");
  cc1101initialize();
  yield();

  if (ELECHOUSE_cc1101.getCC1101()) {
    Serial.println("CC1101 OK");
  } else {
    Serial.println("CC1101 ERROR!");
    while(1) {
      delay(1000);
    }
  }
  
  ELECHOUSE_cc1101.SetRx();
  delay(100);
  
  Serial.println("=== Car Receiver Ready ===\n");
}

void loop() {
  // CRITICAL: Feed watchdog FIRST and use delay to prevent tight looping
  delay(50); // Feed watchdog and slow down loop
  yield();
  
  byte rxBuffer[64]; // Buffer for received data

  if (ELECHOUSE_cc1101.CheckRxFifo(100)) { // Use 100ms timeout instead of 0
    yield();
    
    byte len = ELECHOUSE_cc1101.ReceiveData(rxBuffer);
    
    if (len > 0) {
      Serial.printf("\n[RX] Received %d bytes\n", len);
      yield();
      
      if (len == sizeof(Packet)) {
        Packet pkt;
        memcpy(&pkt, rxBuffer, sizeof(Packet));
        
        yield(); // Feed before validation (this can take time)
        
        if (validatePacket(pkt)) {
          Serial.println("[OK] Packet VALID");
          yield();
          
          if (pkt.action == ACTION_UNLOCK) {
            unlockCar();
          } else if (pkt.action == ACTION_LOCK) {
            lockCar();
          }
        } else {
          Serial.println("[FAIL] Packet INVALID");
        }
      } else {
        Serial.printf("[ERR] Wrong packet size: %d (expected %d)\n", len, sizeof(Packet));
      }
      
      yield();
      
      // Return to receive mode
      ELECHOUSE_cc1101.SetRx();
      delay(50);
    }
  }
  
  yield(); // Final yield before loop repeats
}