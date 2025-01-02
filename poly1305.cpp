#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

namespace Poly1305 {
  typedef uint8_t Key[16];
  typedef uint8_t Acc[17];
  struct State {
    Key r;
    Key s;
    
  };
  
  // 0x 3fffffffffffffffffffffffffffffffb
  const uint8_t p[17] = {0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			 0x03};
  
  void ClampKey(struct Poly1305::State &state);
}

void Poly1305::ClampKey(struct Poly1305::State &state){
  state.r[3]  &= 0x0f;
  state.r[7]  &= 0x0f;
  state.r[11] &= 0x0f;
  state.r[15] &= 0x0f;
  state.r[4]  &= 0xfc;
  state.r[8]  &= 0xfc;
  state.r[12] &= 0xfc;
}

void hexdump(uint8_t *data, size_t length){
  for(int i = 0; i < length; i++){
    std::cout << std::setw(2) << std::setfill('0') << std::hex <<
      static_cast<int>(data[i]) << " ";
    if((i+1) % 16 == 0) std::cout << std::endl;
  }
  std::cout << std::endl;
}


/* Multiply multiword for poly1305 step (Hacker's Delight)*/
void mulmw(uint8_t x[16], uint8_t y[16], uint8_t z[32]){
  for(int i = 0; i < 32; i++) z[i] = 0;
  for(int ix = 0; ix < 16; ix++){
    uint16_t k = 0; //overflow bits
    uint16_t t = 0; //intermediate result
    for(int iy = 0; iy < 16; iy++){
      t = x[ix] * y[iy] + z[ix+iy] + k;
      z[ix+iy] = t; //truncate result
      k = t >> 8; //store the overflow to add when doing next byte
    }
    z[ix + 16] = k;
  }
  
}

/* Add multiword, with any lengths*/
int addmw(uint8_t *x, size_t lx, uint8_t *y, size_t ly, uint8_t *z, size_t lz){
  uint16_t t = 0;
  uint16_t k = 0;
  //shorter of the 2 lengths
  uint8_t size = lx < ly ? lx : ly;
  uint8_t offset = lz - size;
  if (lz < size) {
    return -1;
  }
  for(int i = 0; i < lz; i++) z[i] = 0;
  for(int i = 0; i < size; i++){
    t = x[i] + y[i] + k;
    z[i+offset-1] = t; // truncate result
    k = t >> 8;
  }
  z[lz-1] = k;
  return 0;
}

int main(){

  uint8_t x[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xFF};
  uint8_t y[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  uint8_t z[32];

  mulmw(x, y, z);
  hexdump(z, 32);

  addmw(x, 16, y, 16, z, 32);
  hexdump(z, 32);


  return 0;


  
  struct Poly1305::State state = {
    .r = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8 },
    .s = { 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b }
  };
  
  std::cout << "r is" << std::endl;
  hexdump(state.r, 16);
  std::cout << "s is" << std::endl;
  hexdump(state.s, 16);
  Poly1305::ClampKey(state);
  std::cout << "r is" << std::endl;
  hexdump(state.r, 16);

  return 0;

}
