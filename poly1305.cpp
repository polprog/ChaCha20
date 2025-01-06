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


/* Multiply multiword (Hacker's Delight), unsigned*/
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

/* Add multiword, with any lengths, unsigned*/
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
  int iz, ix, iy;
  for(iz = lz, ix = lx, iy = ly; iz >= 0 && ix >= 0 && iy >= 0; ix--, iy--, iz--){
    t = x[ix] + y[iy] + k;
    z[iz] = t; // truncate result
    k = t >> 8;
  }
  z[iz] = k;

  printf("iz at end = %d\n", iz);
  
  // Carry through longer operand
  uint8_t *longer = lx < ly ? y : x;
  uint8_t lsz = lx < ly ? ly : lx;
  for(int i = iz; i >= 0; i--){
    printf("carry thru\n");
    z[iz] += longer[i];
  }
  return 0;
}


/* Number of leading zero bytes */
size_t nlzb(uint8_t *n, uint8_t nl){
  int i;
  for(i = 0; i < nl && (n[i] == 0); i++);
  return i;
}

/* Number of leading zeros */
uint8_t nlz(uint8_t n){
  uint8_t masks[] = {0x00, 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff};
  int i = 0;
  for(i = 0; i < 8 && (n & masks[i]) != n ; i++);
  return 8-i;
}

// Assume x > y, unsigned
int submw(uint8_t *x, size_t lx, uint8_t *y, size_t ly, uint8_t *z, size_t lz){

  // temporary x to borrow from
  uint8_t *t = (uint8_t*) alloca(lx);
  for(int i = 0; i < lx; i++) t[i] = x[i];
  for(int i = 0; i < lz; i++) z[i] = 0;

  
  for(int ix = lx-1, iy = ly-1, iz = lz-1; ix >= 0 ; ix--, iy--, iz--){
    //printf("t[%d] = %02x, y[%d] = %02x\n", ix, t[ix], iy, y[iy]);
    // z[i] = x[i] - y[i]
    // if x[i] < y[i], then borrow
    uint16_t k = t[ix];
    
    if(t[ix] < y[iy]) {
      //borrow
      bool gotit = false;
      for(int j = ix; j > 0 && !gotit; j--){
	if(t[j-1] > 0x00) {
	  t[j-1] -= 1;
	  gotit = true;
	  //printf("borrowed from position %d\n", j-1);
	  break;
	}
	t[j] = 0xff;
	
      }
      k+= 0x100;
    }
    
    z[iz] = k - y[iy];

  }
  return 0;
}

/* Compare multiword
   Return 1 if a > b,
         -1 if a < b,
	  0 if a == b
*/
int cmpmw(uint8_t *a, size_t la, uint8_t *b, size_t lb){
  //printf("cmpmw: la = %d\tlb=%d\n", la, lb);

  int lza = nlzb(a, la);
  int lzb = nlzb(b, lb);
  
  int i = lza < lzb ? lza : lzb; 

  for(; i < la && i < lb; i++){
    if(a[i] > b[i]) return 1;
    if(a[i] < b[i]) return -1;
  }
  
  return 0;
}

/*
  Return a/b = q mod r
  Assume a > b
*/
int f(uint8_t *a, size_t la, uint8_t *b, size_t lb, uint8_t *q, size_t lq){
  size_t d, dp;
  size_t ld; // length of divisor without leading zeros
  uint8_t *div; //divisor without leading zeros
  size_t lt; // length of temporaries
  int i;
  for(i = 0; i < la && (a[i] == 0); i++);
  d = i;
  dp = nlz(a[i]);
  printf("dividend has %d*8+%d leading zeros\n", d, dp);

  for(i = 0; i < lb && (b[i] == 0); i++);
  ld = la-i;
  printf("divisor has %d lzB\n", ld);
  div = &b[la-ld];
  printf("divisor = "); hexdump(div, ld);
  lt = ld+1;
  printf("temporaries will be %d B long\n", lt);
  
  // Temporary values used in the multiply and substract routine
  uint8_t *u = (uint8_t *) alloca(lt);
  uint8_t *v = (uint8_t *) alloca(lt);
  uint8_t *w = (uint8_t *) alloca(lt);

  uint8_t qdig; // quotient digit
  memset(u, 0, lt);
  memset(v, 0, lt);
  memset(w, 0, lt);

  for(int i = nlzb(a, la), j = 1; j <= ld; i++, j++){
    u[j] = a[i];
  }
  for(int i = d; i+lt-2 < la; i++){
    printf("u= "); hexdump(u, lt);
    // Find quotient digit
    qdig = 0;
    
    while(qdig < 20){
      printf("\t\t\tu= "); hexdump(u, lt);

      printf("   v= "); hexdump(v, lt);
      printf(" + d=    "); hexdump(div, ld);
      printf("----------------------\n");
      addmw(div, ld, v, lt, w, lt);
      printf(" = w= "); hexdump(w, lt);

      printf( "  u>w? = %d\n\n", cmpmw(u, lt, w, lt));
      
      if( cmpmw(u, lt, w, lt) <= 0 ) break;
      memcpy(v, w, lt);
      qdig++;
    }
    submw(u, lt, v, lt, w, lt);
    printf("\t\t\tquotient digit = %02x\n", qdig);
    q[i] = qdig;
    printf(" >>> end   v= "); hexdump(v, lt);    
    printf(" >>> u-v = w= "); hexdump(w, lt);
    // w now contains the intermediate modulus
    // Shift it one byte left and carry next byte from top
    for(int j = 0; j < lt-1; j++) w[j] = w[j+1];
    w[lt-1] = a[i+lt-1];
    printf(" >>> carry w= "); hexdump(w, lt);
    memcpy(u, w, lt);
    printf("=======================\n");
  }
  // TODO znalezc blad
  // dla drugiego stosiku, u = 012333, dochodzi do w = 011fee, ale dostaje wtedy quiotent = 11 a powinno być 12.
  
  
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

  uint8_t k1[4] = {0, 0, 0, 0xff};
  uint8_t k2[5] = {0, 0, 0, 0, 0xff};

  uint8_t aaa[3] = {0x01, 0x23, 0x33};
  uint8_t bbb[3] = {0, 0x1f, 0xfe};
  
  uint8_t z[32];
  uint8_t zz[32];
  for(int i = 0; i < 32; i++) z[i] = 0, zz[i] = 0;

  submw(aaa, 3, bbb, 3, zz, 32);
  printf("012333 - 001ffe = ");
  hexdump(zz, 32);
  printf("012333 cmp 001ffe = %d\n", cmpmw(aaa, 3, bbb, 3));
  
  
  //return 0;			
  
  /*
  mulmw(x, y, z);
  hexdump(z, 32);

  addmw(x, 16, y, 16, z, 32);
  hexdump(z, 32);

  printf("nlz(%08b) = %d\n", 0x01, nlz(0x01));
  printf("nlz(%08b) = %d\n", 0x02, nlz(0x02));
  printf("nlz(%08b) = %d\n", 0x04, nlz(0x04));
  */

  //ubmw(a, 16, b, 16, z, 16);
  
  // k / j  = z mod zz
  //f(k, 16, j, 16, z, 32);
  
  //hexdump(z, 32);
  //hexdump(zz, 32);
  //submw(d, 16, c, 16, z, 16);
  // hexdump(z, 32);

  // printf("cmpmw(a, b) = %d\n", cmpmw(a, 16, b, 16));
  // printf("cmpmw(b, a) = %d\n", cmpmw(b, 16, a, 16));
  // printf("cmpmw(a, a) = %d\n", cmpmw(a, 16, a, 16));

  // printf("cmpmw(k1, k2) = %d\n", cmpmw(k1, 4, k2, 5));
  /*
  hexdump(x, 16);
  //addmw(x, 16, y, 16, x, 16);
  //hexdump(x, 16);
  addmw(k1, 4, k, 16, z, 32);
  hexdump(k1, 4);
  hexdump(k, 16);
  hexdump(z, 32);

  addmw(k, 16, k1, 4, z, 32);
  hexdump(k1, 4);
  hexdump(k, 16);
  hexdump(z, 32);
  */

  
  
  printf("test div: k/j = z\n");
  printf("  k= ");   hexdump(k, 16);
  printf("  j= ");   hexdump(j, 16);
  
  f(k, 16, j, 16, z, 32);
  
  
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
