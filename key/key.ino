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

// Buttons
#define BTN_UNLOCK D3   // GPIO0
#define BTN_LOCK   D4   // GPIO2

// EEPROM
#define EEPROM_ADDR 0
#define EEPROM_SAVE_INTERVAL 10

// Debouncing
#define DEBOUNCE_DELAY 200  // Increased debounce

static const uint32_t CAR_ID    = 0xCAFEBABE;
static const uint32_t KEYFOB_ID = 0x12345678;

static const uint8_t  ROLLING_KEY[16] = {
  0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
  0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

static const uint8_t  TOTP_SECRET[20] = {
  0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x12,0x34,
  0x56,0x78,0x9A,0xBC
};

// Packet structure
struct Packet {
  uint32_t carID;
  uint32_t keyfobID;
  uint8_t  action;
  uint32_t rollingCode;
  uint32_t totp;
};

// Global buffer for received data
uint8_t cc1101_data_buffer[61];

uint32_t rollingCounter = 0;
uint32_t lastSavedCounter = 0;
int32_t timeOffset = 0;

// Debouncing variables
unsigned long lastUnlockPress = 0;
unsigned long lastLockPress = 0;
bool unlockProcessed = false;
bool lockProcessed = false;

// Pre-initialized crypto objects to avoid re-initialization overhead
AES128 aes;
SHA256 sha256;

// defining PINs set for ESP8266 - WEMOS D1 MINI module
byte sck = 14;
byte miso = 12;
byte mosi = 13;
byte ss = 15;
int gdo0 = 5;
int gdo2 = 4;

static void cc1101initialize(void)
{
    ELECHOUSE_cc1101.setSpiPin(sck, miso, mosi, ss);
    ELECHOUSE_cc1101.setGDO(gdo0, gdo2);

    ELECHOUSE_cc1101.Init();
    ELECHOUSE_cc1101.setGDO0(gdo0);
    ELECHOUSE_cc1101.setCCMode(1);
    ELECHOUSE_cc1101.setModulation(2);
    ELECHOUSE_cc1101.setMHZ(433.92);
    ELECHOUSE_cc1101.setDeviation(47.60);
    ELECHOUSE_cc1101.setChannel(0);
    ELECHOUSE_cc1101.setChsp(199.95);
    ELECHOUSE_cc1101.setRxBW(812.50);
    ELECHOUSE_cc1101.setDRate(9.6);
    ELECHOUSE_cc1101.setPA(10);
    ELECHOUSE_cc1101.setSyncMode(2);
    ELECHOUSE_cc1101.setSyncWord(211, 145);
    ELECHOUSE_cc1101.setAdrChk(0);
    ELECHOUSE_cc1101.setAddr(0);
    ELECHOUSE_cc1101.setWhiteData(0);
    ELECHOUSE_cc1101.setPktFormat(0);
    ELECHOUSE_cc1101.setLengthConfig(1);
    ELECHOUSE_cc1101.setPacketLength(0);
    ELECHOUSE_cc1101.setCrc(0);
    ELECHOUSE_cc1101.setCRC_AF(0);
    ELECHOUSE_cc1101.setDcFilterOff(0);
    ELECHOUSE_cc1101.setManchester(0);
    ELECHOUSE_cc1101.setFEC(0);
    ELECHOUSE_cc1101.setPRE(0);
    ELECHOUSE_cc1101.setPQT(0);
    ELECHOUSE_cc1101.setAppendStatus(0);
}

uint32_t generateRollingCode(uint32_t counter) {
  yield(); // Feed watchdog before crypto operation
  
  aes.setKey(ROLLING_KEY, 16); 
  yield(); // Feed watchdog after setKey
  
  uint8_t input[16] = {0}; 
  memcpy(input, &counter, sizeof(counter));
  
  uint8_t out[16];
  aes.encryptBlock(out, input);
  
  yield(); // Feed watchdog after encryption
  
  return *(uint32_t*)out; 
}

uint32_t generateTOTP(uint32_t epoch) {
  yield(); // Feed watchdog before crypto operation
  
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = epoch & 0xFF;
    epoch >>= 8;
  }
  
  sha256.resetHMAC(TOTP_SECRET, sizeof(TOTP_SECRET));
  yield(); // Feed watchdog after reset
  
  sha256.update(msg, 8);
  yield(); // Feed watchdog after update
  
  uint8_t hash[SHA256::HASH_SIZE]; 
  sha256.finalizeHMAC(TOTP_SECRET, sizeof(TOTP_SECRET), hash, sizeof(hash));
  yield(); // Feed watchdog after finalize
  
  int offset = hash[SHA256::HASH_SIZE - 1] & 0x0F; 

  uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset+1] & 0xFF) << 16) |
                    ((hash[offset+2] & 0xFF) << 8) |
                    (hash[offset+3] & 0xFF);
                    
  return binary % 1000000;
}

void saveCounterIfNeeded() {
  if (rollingCounter - lastSavedCounter >= EEPROM_SAVE_INTERVAL) {
    yield();
    EEPROM.put(EEPROM_ADDR, rollingCounter);
    EEPROM.commit();
    lastSavedCounter = rollingCounter;
    Serial.printf("Counter saved: %lu\n", rollingCounter);
  }
}

void sendPacket(uint8_t action) {
  yield(); // Feed watchdog at start
  
  Serial.printf("Building packet (action=%d, counter=%lu)...\n", action, rollingCounter);
  
  Packet pkt;
  pkt.carID = CAR_ID;
  pkt.keyfobID = KEYFOB_ID;
  pkt.action = action;
  
  yield(); // Feed before crypto
  pkt.rollingCode = generateRollingCode(rollingCounter++);
  
  yield(); // Feed before TOTP
  uint32_t epoch = (millis()/1000 + timeOffset) / 30;
  pkt.totp = generateTOTP(epoch);

  yield(); // Feed before sending
  Serial.printf("Sending: RC=%lu, TOTP=%lu\n", pkt.rollingCode, pkt.totp);

  ELECHOUSE_cc1101.SendData((uint8_t*)&pkt, sizeof(pkt));
  delay(100); // Wait for TX, also feeds watchdog
  
  Serial.println("Packet sent");

  saveCounterIfNeeded();
}

void listenForSync() {
  Serial.println("Listening for sync...");
  unsigned long start = millis();
  
  while (millis() - start < 1500) {  // Reduced to 1.5 seconds
      yield(); // CRITICAL
      
      if (ELECHOUSE_cc1101.CheckRxFifo(50)) {  // 50ms timeout
          yield();
          byte len = ELECHOUSE_cc1101.ReceiveData(cc1101_data_buffer); 
          
          if (len == sizeof(int32_t)) {
              int32_t newOffset;
              memcpy(&newOffset, cc1101_data_buffer, sizeof(int32_t)); 
              timeOffset = newOffset;
              Serial.printf("Sync received! offset=%ld\n", timeOffset);
              return;
          }
      }
      
      delay(100); // Longer delay between checks
  }
  Serial.println("No sync");
}

void setup() 
{
  // Disable watchdog immediately
  ESP.wdtDisable();
  
  Serial.begin(115200);
  delay(200);
  
  Serial.println("\n\n=== Keyfob Starting ===");
  
  EEPROM.begin(512);
  yield();

  pinMode(BTN_UNLOCK, INPUT_PULLUP);
  pinMode(BTN_LOCK, INPUT_PULLUP);
  yield();

  EEPROM.get(EEPROM_ADDR, rollingCounter);
  lastSavedCounter = rollingCounter;
  Serial.printf("Rolling counter: %lu\n", rollingCounter);
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
  
  Serial.println("=== Ready ===\n");
}

void loop() 
{
  yield(); // Feed watchdog at start of every loop
  
  unsigned long currentTime = millis();
  
  // Handle UNLOCK button
  bool unlockPressed = (digitalRead(BTN_UNLOCK) == LOW);
  
  if (unlockPressed && !unlockProcessed) {
    if (currentTime - lastUnlockPress > DEBOUNCE_DELAY) {
      Serial.println("\n>>> UNLOCK <<<");
      
      // Disable interrupts during critical section
      noInterrupts();
      ELECHOUSE_cc1101.SetTx();
      interrupts();
      
      delay(50);
      yield();
      
      sendPacket(ACTION_UNLOCK);
      
      noInterrupts();
      ELECHOUSE_cc1101.SetRx();
      interrupts();
      
      delay(50);
      yield();
      
      listenForSync();
      
      unlockProcessed = true;
      lastUnlockPress = currentTime;
      
      Serial.println(">>> Done <<<\n");
    }
  } else if (!unlockPressed) {
    unlockProcessed = false;
  }
  
  yield(); // Feed watchdog between button checks
  
  // Handle LOCK button
  bool lockPressed = (digitalRead(BTN_LOCK) == LOW);
  
  if (lockPressed && !lockProcessed) {
    if (currentTime - lastLockPress > DEBOUNCE_DELAY) {
      Serial.println("\n>>> LOCK <<<");
      
      noInterrupts();
      ELECHOUSE_cc1101.SetTx();
      interrupts();
      
      delay(50);
      yield();
      
      sendPacket(ACTION_LOCK);
      
      noInterrupts();
      ELECHOUSE_cc1101.SetRx();
      interrupts();
      
      delay(50);
      yield();
      
      listenForSync();
      
      lockProcessed = true;
      lastLockPress = currentTime;
      
      Serial.println(">>> Done <<<\n");
    }
  } else if (!lockPressed) {
    lockProcessed = false;
  }
  
  delay(50); // Prevent tight looping, feeds watchdog
}