// Group 2, Genavieve Holmberg, Michael Miller, Nathan Reichert
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <bitset>
#include <math.h>

using namespace std;
typedef unsigned int uint4;

const int S = 8;
const int W = 32;
const int LENGTH = 448;

const uint4 A = 0x67452301;
const uint4 B = 0xefcdab89;
const uint4 C = 0x98badcfe;
const uint4 D = 0x10325476;

uint4 F(uint4 x, uint4 y, uint4 z);
uint4 G(uint4 x, uint4 y, uint4 z);
uint4 H(uint4 x, uint4 y, uint4 z);
uint4 I(uint4 x, uint4 y, uint4 z);

void FF(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]);
void GG(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]);
void HH(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]);
void II(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]);

string hashCode(unsigned char digest[]);
void process_message(uint4 state[], uint4 T[], uint4 X[]);
string pad_message(string message);
void digestMessage(string binMessage, string M[], uint4 X[]);
void init_array(uint4 T[]);
string md5(string message);
void uint_to_uchar(unsigned char digest[], uint4 state[]);

string md5(string message){

	string M[16];
	uint4 X[16] = {0};
	uint4 T[64];
	unsigned char digest[16];

	uint4 state[4];
	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;



	string paddedMessage = pad_message(message);

	digestMessage(paddedMessage, M, X);

	init_array(T);

	for(int i = 0; i < 1000; i++)
	{
		process_message(state, T, X);
	}

	uint_to_uchar(digest, state);

  	string hashedMessage = hashCode(digest);

  return hashedMessage;

}

void uint_to_uchar(unsigned char digest[], uint4 state[]){

  for (int i = 0, j = 0; j < 16; i++, j += 4) {
    digest[j] = state[i] & 255;		// get first byte 
    digest[j+1] = (state[i] >> 8) & 255;	// get second byte
    digest[j+2] = (state[i] >> 16) & 255;	// get third byte
    digest[j+3] = (state[i] >> 24) & 255;	// get fourth byte
  }	

}

string hashCode(unsigned char digest[]){

  // output hash value
  char buffer[33];
  for(int i = 0; i < 16; i++)
  	sprintf(buffer+i*2, "%02x", digest[i]);
  buffer[32] = 0;

  return string(buffer);

}

void process_message(uint4 state[], uint4 T[], uint4 X[]){

	// Process Message
	uint4 a = state[0], b = state[1], c = state[2], d = state[3];

	//* Round 1 *//
	FF(a, b, c, d, 0, 7, 1, X, T);
	FF(d, a, b, c, 1, 12, 2, X, T);
	FF(c, d, a, b, 2, 17, 3, X, T);
	FF(b, c, d, a, 3, 22, 4, X, T);
	FF(a, b, c, d, 4, 7, 5, X, T);
	FF(d, a, b, c, 5, 12, 6, X, T);
	FF(c, d, a, b, 6, 17, 7, X, T);
	FF(b, c, d, a, 7, 22, 8, X, T);	
	FF(a, b, c, d, 8, 7, 9, X, T);
	FF(d, a, b, c, 9, 12, 10, X, T);
	FF(c, d, a, b, 10, 17, 11, X, T);
	FF(b, c, d, a, 11, 22, 12, X, T);
	FF(a, b, c, d, 12, 7, 13, X, T);
	FF(d, a, b, c, 13, 12, 14, X, T);
	FF(c, d, a, b, 14, 17, 15, X, T);
	FF(b, c, d, a, 15, 22, 16, X, T);

	//* Round 2 */
	GG(a, b, c, d, 1, 5, 17, X, T);
	GG(d, a, b, c, 6, 9, 18, X, T);
	GG(c, d, a, b, 11, 14, 19, X, T);
	GG(b, c, d, a, 0, 20, 20, X, T);
	GG(a, b, c, d, 5, 5, 21, X, T);
	GG(d, a, b, c, 10, 9, 22, X, T);
	GG(c, d, a, b, 15, 14, 23, X, T);
	GG(b, c, d, a, 4, 20, 24, X, T);	
	GG(a, b, c, d, 9, 5, 25, X, T);
	GG(d, a, b, c, 14, 9, 26, X, T);
	GG(c, d, a, b, 3, 14, 27, X, T);
	GG(b, c, d, a, 8, 20, 28, X, T);
	GG(a, b, c, d, 13, 5, 29, X, T);
	GG(d, a, b, c, 2, 9, 30, X, T);
	GG(c, d, a, b, 7, 14, 31, X, T);
	GG(b, c, d, a, 12, 20, 32, X, T);

	//* Round 3 */
	HH(a, b, c, d, 5, 4, 33, X, T);
	HH(d, a, b, c, 8, 11, 34, X, T);
	HH(c, d, a, b, 11, 16, 35, X, T);
	HH(b, c, d, a, 14, 23, 36, X, T);
	HH(a, b, c, d, 1, 4, 37, X, T);
	HH(d, a, b, c, 4, 11, 38, X, T);
	HH(c, d, a, b, 7, 16, 39, X, T);
	HH(b, c, d, a, 10, 23, 40, X, T);	
	HH(a, b, c, d, 13, 4, 41, X, T);
	HH(d, a, b, c, 0, 11, 42, X, T);
	HH(c, d, a, b, 3, 16, 43, X, T);
	HH(b, c, d, a, 6, 23, 44, X, T);
	HH(a, b, c, d, 9, 4, 45, X, T);
	HH(d, a, b, c, 12, 11, 46, X, T);
	HH(c, d, a, b, 15, 16, 47, X, T);
	HH(b, c, d, a, 2, 23, 48, X, T);

	//* Round 4 */
	II(a, b, c, d, 0, 6, 49, X, T);
	II(d, a, b, c, 7, 10, 50, X, T);
	II(c, d, a, b, 14, 15, 51, X, T);
	II(b, c, d, a, 5, 21, 52, X, T);
	II(a, b, c, d, 12, 6, 53, X, T);
	II(d, a, b, c, 3, 10, 54, X, T);
	II(c, d, a, b, 10, 15, 55, X, T);
	II(b, c, d, a, 1, 21, 56, X, T);	
	II(a, b, c, d, 8, 6, 57, X, T);
	II(d, a, b, c, 15, 10, 58, X, T);
	II(c, d, a, b, 6, 15, 59, X, T);
	II(b, c, d, a, 13, 21, 60, X, T);
	II(a, b, c, d, 4, 6, 61, X, T);
	II(d, a, b, c, 11, 10, 62, X, T);
	II(c, d, a, b, 2, 15, 63, X, T);
	II(b, c, d, a, 9, 21, 64, X, T);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;	

}


string pad_message(string message){

	string binMessage = "";
	string bitLength = "";

	// Get binary representation of Message
	for(int i = 0; i < message.size(); i++){
		binMessage += bitset<S>(message.c_str()[i]).to_string();
	}

	// Append Padding Bits
	if(binMessage.size() < LENGTH){
		binMessage += '1';

		for(int i = binMessage.size(); i < LENGTH; i++){
			binMessage += '0';
		}
	}


	int m = message.size() << 3;

	// Append Message Length
	bitLength += bitset<64>(m).to_string();

	binMessage += bitLength;	

	return binMessage;

}

void digestMessage(string binMessage, string M[], uint4 X[]){

	// Get 16 32 bit words
	int index = 0;
	for(int i = 0; i < 16; i++){
		for(int j = 0; j < 32; j++){
			M[i] += binMessage.substr()[index];
			index++;
		}
	}

	// string to unsigned int
	for(int i = 0; i < 16; i++){
		stringstream stream(M[i]);
		stream >> X[i];
	}

}

void init_array(uint4 T[]){

	// T[i] = abs(sin(i+1) * 2^32)
	// Generate 64 elements of T for transform
	for(int i = 0; i < 64; i++){
		int v = sin(i + 1);
		v  = pow(2, 32);
		T[i] = abs(v);
	}	
}

uint4 F(uint4 x, uint4 y, uint4 z){
	return ((x & y) | (~x & z));
}


uint4 G(uint4 x, uint4 y, uint4 z){
	return ((x & z) | (y & ~z));
}

uint4 H(uint4 x, uint4 y, uint4 z){
	return ((x ^ y ^ z));
}

uint4 I(uint4 x, uint4 y, uint4 z){
	return (y ^ (x | ~z));
}

void FF(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + F(b, c, d) + x[k] + t[i]) << s);
}

void GG(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + G(b, c, d) + x[k] + t[i]) << s);
}

void HH(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + H(b, c, d) + x[k] + t[i]) << s);
}

void II(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + I(b, c, d) + x[k] + t[i]) << s);
}