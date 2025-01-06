#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <alloca.h>
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


uint8_t nlz(uint8_t n){
  uint8_t masks[] = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
  int i = 0;
  for(i = 0; i < 8 &&  (n & masks[i]) != n ; i++);
  return 8-i;
}

// Assume x > y
int submw(uint8_t *x, size_t lx, uint8_t *y, size_t ly, uint8_t *z, size_t lz){

  // temporary x to borrow from
  uint8_t *t = (uint8_t*) alloca(lx);
  for(int i = 0; i < lx; i++) t[i] = x[i];
  for(int i = 0; i < lz; i++) z[i] = 0;

  
  for(int i = lx-1; i >= 0 ; i--){
    printf("i=%d, t[i] = %02x\n", i, t[i]);
    // z[i] = x[i] - y[i]
    // if x[i] < y[i], then borrow
    uint16_t k = t[i];
    
    if(t[i] < y[i]) {
      //borrow
      bool gotit = false;
      for(int j = i; j > 0 && !gotit; j--){
	if(t[j-1] > 0x00) {
	  t[j-1] -= 1;
	  gotit = true;
	  printf("borrowed from position %d\n", j-1);
	}
	t[j] = 0xff;
	
      }
      k+= 0x100;
      printf("t is ");
      hexdump(t, lx);
    }
    
    z[i] = k - y[i];

  }
}


// Assume a > b
int f(uint8_t *a, size_t la, uint8_t *b, size_t lb, uint8_t *q, size_t lq){
  size_t d, dp;
  int i;
  for(i = 0; i < la && (a[i] == 0); i++);
  d = i;
  dp = nlz(a[i]);
  printf("a has %d*8+%d leading zeros\n", d, dp);

  
  
  return 0;
}



int main(){

  uint8_t x[16] = {0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0xff, 0xFF};
  uint8_t y[16] = {0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0xff, 0xff};
  uint8_t k[16] = {0   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33};
  uint8_t j[16] = {0   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0x0f, 0xff};
  uint8_t a[16] = {0   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x01, 0x00, 0x23};
  uint8_t b[16] = {0   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0xff, 0x01};
  uint8_t c[16] = {0   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0x00, 0x01};
  uint8_t d[16] = {0x80   , 0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    0x00, 0x00};

  uint8_t z[32];
  uint8_t zz[32];

  /*
  mulmw(x, y, z);
  hexdump(z, 32);

  addmw(x, 16, y, 16, z, 32);
  hexdump(z, 32);

  printf("nlz(%08b) = %d\n", 0x01, nlz(0x01));
  printf("nlz(%08b) = %d\n", 0x02, nlz(0x02));
  printf("nlz(%08b) = %d\n", 0x04, nlz(0x04));
  */
  for(int i = 0; i < 32; i++) z[i] = 0, zz[i] = 0;

  submw(a, 16, b, 16, z, 16);
  
  // k / j  = z mod zz
  //f(k, 16, j, 16, z, 32);
  
  hexdump(z, 32);
  //hexdump(zz, 32);
  submw(d, 16, c, 16, z, 16);
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
