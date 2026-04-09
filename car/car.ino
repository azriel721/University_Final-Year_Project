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
#define LED_GREEN 16   // GPIO16
#define LED_RED   17   // GPIO17

// EEPROM
#define EEPROM_ADDR 0
#define EEPROM_SAVE_INTERVAL 10
#define ROLLING_WINDOW 256

// TOTP
#define TOTP_INTERVAL 5  // 5 seconds
#define TIME_TOLERANCE 2
#define MSG_TIME_SYNC 0x02

// Security constants
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
uint32_t lastRollingCounter = 0;
uint32_t lastSavedCounter = 0;
uint32_t currentTime = 0;
unsigned long lastSecondUpdate = 0;
unsigned long lastFlush = 0;

// CC1101 pins for ESP32
byte sck = 18;
byte miso = 19;
byte mosi = 23;
byte ss = 5;
int gdo0 = 2;
int gdo2 = 4;

// Crypto objects
AES128 aesRolling;
AES128 aesDecrypt;
SHA256 sha256;

// ================= CC1101 =================

void cc1101initialize(void) {
  Serial.println(F("Initializing CC1101..."));
  
  ELECHOUSE_cc1101.setSpiPin(sck, miso, mosi, ss);
  ELECHOUSE_cc1101.setGDO(gdo0, gdo2);
  
  delay(200);
  ELECHOUSE_cc1101.Init();
  delay(200);

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
  
  Serial.println(F("✓ CC1101 configured"));
}

// ================= CRYPTO =================

uint32_t generateRollingCode(uint32_t counter) {
  aesRolling.setKey(ROLLING_KEY, 16);
  
  uint8_t input[16] = {0};
  memcpy(input, &counter, sizeof(counter));
  
  uint8_t out[16];
  aesRolling.encryptBlock(out, input);
  
  return *(uint32_t*)out;
}

uint32_t generateTOTP(uint32_t epoch) {
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

bool decryptPacket(uint8_t* encrypted, Packet* pkt) {
  uint8_t decrypted[32];
  memset(decrypted, 0, sizeof(decrypted));
  
  aesDecrypt.setKey(PACKET_KEY, 16);
  
  aesDecrypt.decryptBlock(decrypted, encrypted);
  aesDecrypt.decryptBlock(decrypted + 16, encrypted + 16);
  
  memcpy(pkt, decrypted, sizeof(Packet));
  
  return true;
}

uint8_t calcChecksum(uint8_t* data, int len) {
  uint8_t cs = 0;
  for (int i = 0; i < len; i++) cs ^= data[i];
  return cs;
}

// ================= TIME SYNC =================

void sendTimeSync() {
  TimeSyncMessage msg;
  msg.type = MSG_TIME_SYNC;
  msg.timestamp = currentTime;
  msg.checksum = calcChecksum((uint8_t*)&msg, sizeof(TimeSyncMessage) - 1);
  
  // Give keyfob time to switch to RX mode
  delay(300);
  
  ELECHOUSE_cc1101.SetTx();
  delay(50);
  
  // Send unencrypted time sync with dummy bytes
  uint8_t syncBuffer[sizeof(TimeSyncMessage) + 2];
  syncBuffer[0] = 0xAA;
  syncBuffer[1] = 0xBB;
  memcpy(&syncBuffer[2], &msg, sizeof(TimeSyncMessage));
  
  ELECHOUSE_cc1101.SendData(syncBuffer, sizeof(TimeSyncMessage) + 2);
  delay(200);
  
  Serial.println(F("✓ Time sync sent"));
  
  ELECHOUSE_cc1101.SetRx();
  delay(50);
}

// ================= VALIDATION =================

bool verifyTOTP(uint32_t receivedTOTP, uint32_t senderTime) {
  uint32_t ourEpoch = currentTime / TOTP_INTERVAL;
  
  for (int i = -TIME_TOLERANCE; i <= TIME_TOLERANCE; i++) {
    uint32_t testEpoch = ourEpoch + i;
    uint32_t expectedTOTP = generateTOTP(testEpoch);
    
    if (receivedTOTP == expectedTOTP) {
      return true;
    }
  }
  
  return false;
}

bool validatePacket(Packet &pkt) {
  // Check IDs
  if (pkt.carID != CAR_ID) {
    Serial.println(F("✗ Wrong car ID"));
    return false;
  }
  
  if (pkt.keyfobID != KEYFOB_ID) {
    Serial.println(F("✗ Wrong keyfob ID"));
    return false;
  }
  
  // Check rolling code
  bool rollingCodeValid = false;
  
  for (uint16_t offset = 0; offset < ROLLING_WINDOW; offset++) {
    uint32_t testCounter = lastRollingCounter + offset;
    uint32_t expectedRC = generateRollingCode(testCounter);
    
    if (pkt.rollingCode == expectedRC) {
      rollingCodeValid = true;
      lastRollingCounter = testCounter + 1;
      
      if (lastRollingCounter - lastSavedCounter >= EEPROM_SAVE_INTERVAL) {
        EEPROM.put(EEPROM_ADDR, lastRollingCounter);
        EEPROM.commit();
        lastSavedCounter = lastRollingCounter;
      }
      
      break;
    }
  }
  
  if (!rollingCodeValid) {
    Serial.println(F("✗ Invalid rolling code"));
    return false;
  }
  
  // Verify TOTP
  if (!verifyTOTP(pkt.totp, pkt.timestamp)) {
    Serial.println(F("✗ TOTP mismatch"));
    return false;
  }
  
  return true;
}

// ================= LED CONTROL =================

void lockCar() {
  Serial.println(F("\n🔒 CAR LOCKED\n"));
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED, HIGH);
}

void unlockCar() {
  Serial.println(F("\n🔓 CAR UNLOCKED\n"));
  digitalWrite(LED_RED, LOW);
  digitalWrite(LED_GREEN, HIGH);
}

// ================= SETUP =================

void setup() {
  Serial.begin(115200);
  delay(500);
  
  Serial.println(F("\n\n╔═══════════════════════════════╗"));
  Serial.println(F("║  SECURE CAR RECEIVER v6.2     ║"));
  Serial.println(F("╚═══════════════════════════════╝\n"));
  
  EEPROM.begin(512);

  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_RED, OUTPUT);

  lockCar();
  
  EEPROM.get(EEPROM_ADDR, lastRollingCounter);
  
  if (lastRollingCounter == 0xFFFFFFFF || lastRollingCounter > 0xFFFFFF00) {
    Serial.println(F("⚠ Counter reset"));
    lastRollingCounter = 0;
    EEPROM.put(EEPROM_ADDR, lastRollingCounter);
    EEPROM.commit();
  }
  
  lastSavedCounter = lastRollingCounter;
  Serial.printf("Counter: %lu\n", lastRollingCounter);

  cc1101initialize();

  if (!ELECHOUSE_cc1101.getCC1101()) {
    Serial.println(F("✗ CC1101 FAILED"));
    while(1) {
      delay(1000);
    }
  }
  
  Serial.println(F("✓ CC1101 OK"));
  
  ELECHOUSE_cc1101.SetRx();
  delay(100);
  
  Serial.println(F("✓ Listening...\n"));
  
  lastSecondUpdate = millis();
  lastFlush = millis();
}

// ================= LOOP =================

void loop() {
  // Update time
  if (millis() - lastSecondUpdate >= 1000) {
    currentTime++;
    lastSecondUpdate = millis();
  }
  
  // Flush junk periodically
  if (millis() - lastFlush > 1000) {
    byte rxBytes = ELECHOUSE_cc1101.SpiReadReg(0x3B) & 0x7F;
    if (rxBytes > 0 && rxBytes < 32) {
      ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
      delay(2);
      ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
      delay(2);
      ELECHOUSE_cc1101.SetRx();
      delay(5);
    }
    lastFlush = millis();
  }
  
  // Check for packets
  byte rxBytes = ELECHOUSE_cc1101.SpiReadReg(0x3B) & 0x7F;
  
  if (rxBytes >= 32) {
    int rssi = ELECHOUSE_cc1101.getRssi();
    
    // Only process strong signals
    if (rssi > -70) {
      uint8_t rxBuffer[256];
      memset(rxBuffer, 0, sizeof(rxBuffer));
      
      int len = ELECHOUSE_cc1101.ReceiveData(rxBuffer);
      
      if (len >= 34) {
        // Try to find the actual packet by looking for the dummy bytes (0xAA 0xBB)
        int packetStart = 0;
        
        for (int i = 0; i < min(10, len - 32); i++) {
          if (rxBuffer[i] == 0xAA && i + 1 < len && rxBuffer[i + 1] == 0xBB) {
            packetStart = i + 2;
            break;
          }
        }
        
        // If we have enough bytes after the offset
        if (len >= packetStart + 32) {
          uint8_t encryptedPacket[32];
          memcpy(encryptedPacket, rxBuffer + packetStart, 32);
          
          Packet pkt;
          memset(&pkt, 0, sizeof(pkt));
          
          if (decryptPacket(encryptedPacket, &pkt)) {
            Serial.println(F("\n✓ Packet received"));
            
            if (validatePacket(pkt)) {
              Serial.println(F("✓ Authentication successful"));
              
              if (pkt.action == ACTION_UNLOCK) {
                unlockCar();
              } else if (pkt.action == ACTION_LOCK) {
                lockCar();
              }
              
              // Flush and send time sync
              ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
              delay(5);
              ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
              delay(5);
              
              sendTimeSync();
              
            } else {
              Serial.println(F("✗ Authentication failed"));
              
              // Still send time sync to help with desync issues
              ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
              delay(5);
              ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
              delay(5);
              
              sendTimeSync();
            }
          }
        } else {
          // Flush on error
          ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
          delay(5);
          ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
          delay(5);
          ELECHOUSE_cc1101.SetRx();
          delay(10);
        }
      } else {
        // Flush on error
        ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
        delay(5);
        ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
        delay(5);
        ELECHOUSE_cc1101.SetRx();
        delay(10);
      }
    } else {
      // Weak signal, flush
      ELECHOUSE_cc1101.SpiStrobe(0x36); // SIDLE
      delay(2);
      ELECHOUSE_cc1101.SpiStrobe(0x3A); // SFRX
      delay(2);
      ELECHOUSE_cc1101.SetRx();
      delay(5);
    }
  }
  
  delay(50);
}
