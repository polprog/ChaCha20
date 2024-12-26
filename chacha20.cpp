#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

namespace ChaCha20 {
void QRound(uint32_t *state, int a, int b, int c, int d);
void InnerBlock(uint32_t *state);
void Block(uint32_t *output, const uint32_t *key, uint32_t blockCount,
           const uint32_t *nonce);
} // namespace ChaCha20

void ChaCha20::QRound(uint32_t *state, int a, int b, int c, int d) {
  state[a] += state[b];
  state[d] ^= state[a];
  state[d] = ROTL(state[d], 16);

  state[c] += state[d];
  state[b] ^= state[c];
  state[b] = ROTL(state[b], 12);

  state[a] += state[b];
  state[d] ^= state[a];
  state[d] = ROTL(state[d], 8);

  state[c] += state[d];
  state[b] ^= state[c];
  state[b] = ROTL(state[b], 7);
}

void ChaCha20::InnerBlock(uint32_t *state) {
  // Column rounds
  QRound(state, 0, 4, 8, 12);
  QRound(state, 1, 5, 9, 13);
  QRound(state, 2, 6, 10, 14);
  QRound(state, 3, 7, 11, 15);

  // Diagonal rounds
  QRound(state, 0, 5, 10, 15);
  QRound(state, 1, 6, 11, 12);
  QRound(state, 2, 7, 8, 13);
  QRound(state, 3, 4, 9, 14);
}

void ChaCha20::Block(uint32_t *output, const uint32_t *key, uint32_t blockCount,
                     const uint32_t *nonce) {
  // Constants "expand 32-byte k" in little-endian format
  const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32,
                                 0x6b206574};

  uint32_t state[16];

  // Initialize the state
  memcpy(state, constants, sizeof(constants)); // First 4 words: constants
  memcpy(state + 4, key, 32);                  // Next 8 words: key
  state[12] = blockCount;                      // 13th word: block count
  memcpy(state + 13, nonce, 12);               // Last 3 words: nonce

  std::cout << "[ ChaCha20 Block Output ]" << std::endl;
  for (int i = 0; i < 16; ++i) {
    std::cout << std::setw(8) << std::setfill('0') << std::hex << state[i] << " ";
    if ((i + 1) % 4 == 0) {
      std::cout << std::endl;
    }
  }

  uint32_t workingState[16];
  memcpy(workingState, state, sizeof(state));

  // Perform 20 rounds (10 iterations of the inner block)
  for (int i = 0; i < 10; ++i) {
    InnerBlock(workingState);
  }

  // Add the original state to the working state
  for (int i = 0; i < 16; ++i) {
    output[i] = workingState[i] + state[i];
  }
}

void SerializeState(const uint32_t* state, uint8_t* serializedState) {
    for (int i = 0; i < 16; ++i) {
        serializedState[i * 4 + 0] = static_cast<uint8_t>(state[i] & 0xFF);
        serializedState[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        serializedState[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        serializedState[i * 4 + 3] = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
    }
}

void encrypt(uint8_t* plain, int plain_len) {
  
  // Example key, block count, and nonce
  uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                     0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
  uint32_t blockCount = 1;
  uint32_t nonce[3] = {0x09000000, 0x4a000000, 0x00000000};

  uint32_t output[16];
  ChaCha20::Block(output, key, blockCount, nonce);

  // Print the resulting state
  /*
  std::cout << "[ ChaCha20 Block Output ]" << std::endl;
  for (int i = 0; i < 16; ++i) {
    std::cout << std::setw(8) << std::setfill('0') << std::hex << output[i]
              << " ";
    if ((i + 1) % 4 == 0) {
      std::cout << std::endl;
    }
  }*/

  int k = 0;
  int j = 0;
  for (j = 0; j < (plain_len/64); ++j) {
    ChaCha20::Block(output, key, blockCount, nonce);
    blockCount += j;
    
    uint8_t serialized[64] = {0};
    SerializeState(output, serialized);
    int i = 0;
    while (i != 64) {
      plain[k] ^= serialized[i];
      i++; k++;
    }
  }
  if ((plain_len % 64) != 0) {
    ChaCha20::Block(output, key, blockCount, nonce);
    blockCount += j;

    uint8_t serialized[64] = {0};
    SerializeState(output, serialized);
    int i = 0;
    while (i != 64) {
      plain[k] ^= serialized[i];
      i++; k++;
    }
  }
}

int main() {
  uint8_t af[] = "HELLO WORLD\n\00";
  
  for (int i = 0; i < 13; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << 
      static_cast<int>(af[i]) << " ";
    if ((i + 1) % 16 == 0) {
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;

  encrypt(af, 13);

  for (int i = 0; i < 13; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << 
      static_cast<int>(af[i]) << " ";
    if ((i + 1) % 16 == 0) {
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;

  encrypt(af, 13);

  for (int i = 0; i < 13; ++i) {
    std::cout << std::setw(2) << std::setfill('0') << std::hex << 
      static_cast<int>(af[i]) << " ";
    if ((i + 1) % 16 == 0) {
      std::cout << std::endl;
    }
  }
  std::cout << std::endl;

  std::cout << af << std::endl;

  return 0;
}
