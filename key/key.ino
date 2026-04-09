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
#define BTN_UNLOCK 25   // GPIO25
#define BTN_LOCK   26   // GPIO26

// EEPROM
#define EEPROM_ADDR 0
#define EEPROM_SAVE_INTERVAL 10

// Debouncing
#define DEBOUNCE_DELAY 50

// TOTP
#define TOTP_INTERVAL 5
#define MSG_TIME_SYNC 0x02

static const uint32_t CAR_ID    = 0xCAFEBABE;
static const uint32_t KEYFOB_ID = 0x12345678;

static const uint8_t ROLLING_KEY[16] = {
  0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,
  0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
};

static const uint8_t PACKET_KEY[16] = {
  0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
  0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88
};

static const uint8_t TOTP_SECRET[20] = {
  0xAB,0xCD,0xEF,0x01,0x23,0x45,0x67,0x89,
  0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x12,0x34,
  0x56,0x78,0x9A,0xBC
};

// Packet structure
#pragma pack(push, 1)
struct Packet {
  uint32_t carID;
  uint32_t keyfobID;
  uint8_t  action;
  uint32_t rollingCode;
  uint32_t totp;
  uint32_t timestamp;
};

struct TimeSyncMessage {
  uint8_t type;
  uint32_t timestamp;
  uint8_t checksum;
};
#pragma pack(pop)

// Global variables
uint8_t cc1101_data_buffer[61];
uint32_t rollingCounter = 0;
uint32_t lastSavedCounter = 0;
uint32_t currentTime = 0;
unsigned long lastSecondUpdate = 0;

// Debouncing
unsigned long lastUnlockPress = 0;
unsigned long lastLockPress = 0;
bool unlockProcessed = false;
bool lockProcessed = false;

// CC1101 pins
byte sck = 18;
byte miso = 19;
byte mosi = 23;
byte ss = 5;
int gdo0 = 2;
int gdo2 = 4;

// ================= CC1101 =================

void cc1101initialize(void) {
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

// ================= CRYPTO =================

uint32_t generateRollingCode(uint32_t counter) {
  AES128 aes;
  aes.setKey(ROLLING_KEY, 16);
  uint8_t input[16] = {0};
  memcpy(input, &counter, sizeof(counter));
  uint8_t out[16];
  aes.encryptBlock(out, input);
  return *(uint32_t*)out;
}

uint32_t generateTOTP(uint32_t epoch) {
  SHA256 sha256;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = epoch & 0xFF;
    epoch >>= 8;
  }
  
  sha256.resetHMAC(TOTP_SECRET, sizeof(TOTP_SECRET));
  sha256.update(msg, 8);
  uint8_t hash[SHA256::HASH_SIZE];
  sha256.finalizeHMAC(TOTP_SECRET, sizeof(TOTP_SECRET), hash, sizeof(hash));
  
  int offset = hash[SHA256::HASH_SIZE - 1] & 0x0F;
  uint32_t binary = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset+1] & 0xFF) << 16) |
                    ((hash[offset+2] & 0xFF) << 8) |
                    (hash[offset+3] & 0xFF);
  return binary % 1000000;
}

void encryptPacket(const Packet* plainPacket, uint8_t* encryptedData) {
  AES128 aes;
  aes.setKey(PACKET_KEY, 16);
  
  uint8_t plaintext[32];
  memset(plaintext, 0, 32);
  memcpy(plaintext, plainPacket, sizeof(Packet));
  
  aes.encryptBlock(encryptedData, plaintext);
  aes.encryptBlock(encryptedData + 16, plaintext + 16);
}

uint8_t calcChecksum(uint8_t* data, int len) {
  uint8_t cs = 0;
  for (int i = 0; i < len; i++) cs ^= data[i];
  return cs;
}

// ================= PACKET SEND =================

void saveCounterIfNeeded() {
  if (rollingCounter - lastSavedCounter >= EEPROM_SAVE_INTERVAL) {
    EEPROM.put(EEPROM_ADDR, rollingCounter);
    EEPROM.commit();
    lastSavedCounter = rollingCounter;
    Serial.printf("Counter saved: %lu\n", rollingCounter);
  }
}

void sendPacket(uint8_t action) {
  Serial.println(F("\n>>> SENDING PACKET <<<"));
  
  Packet pkt;
  pkt.carID = CAR_ID;
  pkt.keyfobID = KEYFOB_ID;
  pkt.action = action;
  pkt.rollingCode = generateRollingCode(rollingCounter++);
  uint32_t epoch = currentTime / TOTP_INTERVAL;
  pkt.totp = generateTOTP(epoch);
  pkt.timestamp = currentTime;

  Serial.printf("Action: %d, RC: %lu, TOTP: %lu, Time: %lu\n", 
                action, pkt.rollingCode, pkt.totp, currentTime);

  // Encrypt
  uint8_t encryptedPacket[32];
  encryptPacket(&pkt, encryptedPacket);

  // Add dummy bytes
  uint8_t transmitBuffer[34];
  transmitBuffer[0] = 0xAA;
  transmitBuffer[1] = 0xBB;
  memcpy(&transmitBuffer[2], encryptedPacket, 32);

  Serial.println(F("Transmitting..."));
  ELECHOUSE_cc1101.SendData(transmitBuffer, 34);
  
  delay(50);
  
  Serial.println(F("✓ Sent!\n"));

  saveCounterIfNeeded();
}

// ================= TIME SYNC =================

void hardResetRX() {
  ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
  delay(5);
  ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX - flush RX FIFO
  delay(5);
  ELECHOUSE_cc1101.SpiStrobe(0x3B); // SFTX - flush TX FIFO  
  delay(5);
  ELECHOUSE_cc1101.SetRx();
  delay(10);
}

void listenForSync() {
  // Hard reset the RX chain
  hardResetRX();
  
  // Check FIFO is empty
  byte rxBytes = ELECHOUSE_cc1101.SpiReadReg(0x3B) & 0x7F;
  
  if (rxBytes > 0) {
    // Force flush if needed
    ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
    delay(10);
    ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
    delay(10);
    
    // Manually read out junk
    for (int i = 0; i < rxBytes && i < 64; i++) {
      ELECHOUSE_cc1101.SpiReadReg(0x3F);
    }
    delay(10);
    
    ELECHOUSE_cc1101.SetRx();
    delay(20);
  }
  
  unsigned long start = millis();
  
  while (millis() - start < 4000) {
    // Read FIFO status
    byte rxBytes = ELECHOUSE_cc1101.SpiReadReg(0x3B) & 0x7F;
    
    // We need at least 7 bytes: 1 (length) + 6 (TimeSyncMessage)
    if (rxBytes >= 7) {
      // Read the length byte first
      byte firstByte = ELECHOUSE_cc1101.SpiReadReg(0x3F);
      
      // Now read the rest
      int bytesToRead = min((int)firstByte, 60);
      if (bytesToRead > 0 && bytesToRead <= 60) {
        for (int i = 0; i < bytesToRead; i++) {
          cc1101_data_buffer[i] = ELECHOUSE_cc1101.SpiReadReg(0x3F);
        }
        
        // Look for time sync message
        int maxOffset = min(5, bytesToRead - (int)sizeof(TimeSyncMessage));
        
        for (int offset = 0; offset <= maxOffset; offset++) {
          if (offset + sizeof(TimeSyncMessage) > bytesToRead) break;
          
          TimeSyncMessage msg;
          memcpy(&msg, &cc1101_data_buffer[offset], sizeof(TimeSyncMessage));
          
          if (msg.type == MSG_TIME_SYNC) {
            uint8_t expectedChecksum = calcChecksum((uint8_t*)&msg, sizeof(TimeSyncMessage) - 1);
            
            if (msg.checksum == expectedChecksum) {
              Serial.println("✓ Time sync successful");
              Serial.printf("Time updated: %lu -> %lu (diff: %ld sec)\n", 
                          currentTime, msg.timestamp, (int32_t)(msg.timestamp - currentTime));
              
              currentTime = msg.timestamp;
              lastSecondUpdate = millis();
              
              hardResetRX();
              return;
            }
          }
        }
      }
      
      // Reset for next attempt
      hardResetRX();
    }
    
    delay(20);
  }
  
  Serial.println("✗ Time sync failed (timeout)");
  
  // Final cleanup
  hardResetRX();
}

// ================= SETUP =================

void setup() {
  Serial.begin(115200);
  delay(100);
  
  Serial.println(F("\n\n╔═══════════════════════════════╗"));
  Serial.println(F("║   SECURE KEYFOB - ESP32       ║"));
  Serial.println(F("╚═══════════════════════════════╝\n"));
  
  EEPROM.begin(512);

  pinMode(BTN_UNLOCK, INPUT_PULLUP);
  pinMode(BTN_LOCK, INPUT_PULLUP);

  EEPROM.get(EEPROM_ADDR, rollingCounter);
  lastSavedCounter = rollingCounter;
  Serial.printf("Rolling counter: %lu\n", rollingCounter);

  cc1101initialize();

  if (ELECHOUSE_cc1101.getCC1101()) {
    Serial.println(F("✓ CC1101 OK"));
  } else {
    Serial.println(F("✗ CC1101 error!"));
    while(1) {
      delay(1000);
    }
  }
  
  ELECHOUSE_cc1101.SetRx();
  delay(50);
  
  Serial.println(F("✓ Ready!\n"));
  
  lastSecondUpdate = millis();
}

// ================= LOOP =================

void loop() {
  // Update time
  if (millis() - lastSecondUpdate >= 1000) {
    currentTime++;
    lastSecondUpdate = millis();
  }
  
  unsigned long currentMillis = millis();
  
  // UNLOCK button
  bool unlockPressed = (digitalRead(BTN_UNLOCK) == LOW);
  
  if (unlockPressed && !unlockProcessed) {
    if (currentMillis - lastUnlockPress > DEBOUNCE_DELAY) {
      Serial.println("\n=== UNLOCK ===");
      
      ELECHOUSE_cc1101.SetTx();
      delay(100);
      
      sendPacket(ACTION_UNLOCK);
      
      delay(50);
      
      ELECHOUSE_cc1101.SetRx();
      delay(100);
      
      listenForSync();
      
      unlockProcessed = true;
      lastUnlockPress = currentMillis;
    }
  } else if (!unlockPressed) {
    unlockProcessed = false;
  }
  
  // LOCK button
  bool lockPressed = (digitalRead(BTN_LOCK) == LOW);
  
  if (lockPressed && !lockProcessed) {
    if (currentMillis - lastLockPress > DEBOUNCE_DELAY) {
      Serial.println("\n=== LOCK ===");
      
      ELECHOUSE_cc1101.SetTx();
      delay(100);
      
      sendPacket(ACTION_LOCK);
      
      delay(50);
      
      ELECHOUSE_cc1101.SetRx();
      delay(100);
      
      listenForSync();
      
      lockProcessed = true;
      lastLockPress = currentMillis;
    }
  } else if (!lockPressed) {
    lockProcessed = false;
  }
  
  delay(10);
}
