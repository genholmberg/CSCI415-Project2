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

/*
* This method performs the MD5 crypt algorithm on a message.
* Params: This method takes in a string as a parameter.
* Pre: Message must already be defined.
* Post: This method returns a hexadecimal string or the resulting hash code.
*/
string md5(string message){

	string M[16];
	uint4 X[16] = {0};
	uint4 T[64];
	unsigned char digest[16];

	// save the different states to be used during transformation
	uint4 state[4];
	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;



	string paddedMessage = pad_message(message);	// pad message

	digestMessage(paddedMessage, M, X);	// break message into 16 32 bit words

	init_array(T);	// initialize array of 64 elements to be used in transformation

	for(int i = 0; i < 1000; i++)	// slowdown
	{
		process_message(state, T, X);	// perform transformation on message
	}

	uint_to_uchar(digest, state);	// change uint4 to unsigned char

  	string hashedMessage = hashCode(digest);	// get hash code

  return hashedMessage;

}// end md5

/*
* This method converts an unsigned int to unsigned char.
* Params: This method takes in two arrays as parameters.
* Pre: Both arrays must already be loaded with values.
* Post: none.
*/
void uint_to_uchar(unsigned char digest[], uint4 state[]){

char data[256];
  for (int i = 0, j = 0; j < 16; i++, j += 4) {
    digest[j] = state[i] & 255;		// get first byte 
    digest[j+1] = (state[i] >> 8) & 255;	// get second byte
    digest[j+2] = (state[i] >> 16) & 255;	// get third byte
    digest[j+3] = (state[i] >> 24) & 255;	// get fourth byte
  }	// end for
}// end uint_to_uchar

/*
* This method converts the character array to a hexidecimal hash code.
* Params: This method takes in an array of unsigned char.
* Pre: Array must be loaded with values.
* Post: This method returns a 32 byte hexidecimal hash code.
*/
string hashCode(unsigned char digest[]){

  // output hash value
  char buffer[33];
  for(int i = 0; i < 16; i++)
  	sprintf(buffer+i*2, "%02x", digest[i]);	// store hexidecimal value of character in buffer
  buffer[32] = 0;

  return string(buffer);

}// end hashCode


/*
* This method processes the message into 4 different rounds of transformations.
* Params: This method takes in three arrays of type unsigned int.
* Pre: Arrays must already be loaded with values.
* Post: none.
*/
void process_message(uint4 state[], uint4 T[], uint4 X[]){

	// store states into variable to be used in the transformation
	// AA = A  BB = B  CC = C  DD = D
	uint4 a = state[0], b = state[1], c = state[2], d = state[3];

	//* Round 1 *//
	// performs operation 
	// a = b + ((a + F(b, c, d) + x[k] + t[i]) << s)
	FF(a, b, c, d,  0,  7, 0, X, T);
	FF(d, a, b, c,  1, 12, 1, X, T);
	FF(c, d, a, b,  2, 17, 2, X, T);
	FF(b, c, d, a,  3, 22, 3, X, T);
	FF(a, b, c, d,  4,  7, 4, X, T);
	FF(d, a, b, c,  5, 12, 5, X, T);
	FF(c, d, a, b,  6, 17, 6, X, T);
	FF(b, c, d, a,  7, 22, 7, X, T);	
	FF(a, b, c, d,  8,  7, 8, X, T);
	FF(d, a, b, c,  9, 12, 9, X, T);
	FF(c, d, a, b, 10, 17, 10, X, T);
	FF(b, c, d, a, 11, 22, 11, X, T);
	FF(a, b, c, d, 12, 7,  12, X, T);
	FF(d, a, b, c, 13, 12, 13, X, T);
	FF(c, d, a, b, 14, 17, 14, X, T);
	FF(b, c, d, a, 15, 22, 15, X, T);

	//* Round 2 */
	// performs operation
	// a = b + ((a + G(b, c, d) + x[k] + t[i]) << s)
	GG(a, b, c, d, 1,  5,  16, X, T);
	GG(d, a, b, c, 6,  9,  17, X, T);
	GG(c, d, a, b, 11, 14, 18, X, T);
	GG(b, c, d, a, 0,  20, 19, X, T);
	GG(a, b, c, d, 5,  5,  20, X, T);
	GG(d, a, b, c, 10, 9,  21, X, T);
	GG(c, d, a, b, 15, 14, 22, X, T);
	GG(b, c, d, a, 4,  20, 23, X, T);	
	GG(a, b, c, d, 9,  5,  24, X, T);
	GG(d, a, b, c, 14, 9,  25, X, T);
	GG(c, d, a, b, 3,  14, 26, X, T);
	GG(b, c, d, a, 8,  20, 27, X, T);
	GG(a, b, c, d, 13, 5,  28, X, T);
	GG(d, a, b, c, 2,  9,  29, X, T);
	GG(c, d, a, b, 7,  14, 30, X, T);
	GG(b, c, d, a, 12, 20, 31, X, T);

	//* Round 3 */
	// performs operation
	// a = b + ((a + H(b, c, d) + x[k] + t[i]) << s)
	HH(a, b, c, d, 5,  4,  32, X, T);
	HH(d, a, b, c, 8,  11, 33, X, T);
	HH(c, d, a, b, 11, 16, 34, X, T);
	HH(b, c, d, a, 14, 23, 35, X, T);
	HH(a, b, c, d, 1,  4,  36, X, T);
	HH(d, a, b, c, 4,  11, 37, X, T);
	HH(c, d, a, b, 7,  16, 38, X, T);
	HH(b, c, d, a, 10, 23, 39, X, T);	
	HH(a, b, c, d, 13, 4,  40, X, T);
	HH(d, a, b, c, 0,  11, 41, X, T);
	HH(c, d, a, b, 3,  16, 42, X, T);
	HH(b, c, d, a, 6,  23, 43, X, T);
	HH(a, b, c, d, 9,  4,  44, X, T);
	HH(d, a, b, c, 12, 11, 45, X, T);
	HH(c, d, a, b, 15, 16, 46, X, T);
	HH(b, c, d, a, 2,  23, 47, X, T);


	//* Round 4 */
	// performs operation
	// a = b + ((a + I(b, c, d) + x[k] + t[i]) << s)
	II(a, b, c, d, 0,  6,  48, X, T);
	II(d, a, b, c, 7,  10, 49, X, T);
	II(c, d, a, b, 14, 15, 50, X, T);
	II(b, c, d, a, 5,  21, 51, X, T);
	II(a, b, c, d, 12, 6,  52, X, T);
	II(d, a, b, c, 3,  10, 53, X, T);
	II(c, d, a, b, 10, 15, 54, X, T);
	II(b, c, d, a, 1,  21, 55, X, T);
	II(a, b, c, d, 8,  6,  56, X, T);
	II(d, a, b, c, 15, 10, 57, X, T);
	II(c, d, a, b, 6,  15, 58, X, T);
	II(b, c, d, a, 13, 21, 59, X, T);
	II(a, b, c, d, 4,  6,  60, X, T);
	II(d, a, b, c, 11, 10, 61, X, T);
	II(c, d, a, b, 2,  15, 62, X, T);
	II(b, c, d, a, 9,  21, 63, X, T);

	state[0] += a; 	// A = A + AA
	state[1] += b;	// B = B + BB
	state[2] += c;	// C = C + CC
	state[3] += d;	// D = D + DD

}// end process_message

/*
* This method pads the message out to 512 bits.
* Params: This method takes in a string as a parameter.
* Pre: Message must already be defined.
* Post: This method returns a binary string of the padded message.
*/
string pad_message(string message){

	string binMessage = "";
	string bitLength = "";

	// Get binary representation of Message
	for(int i = 0; i < message.length(); i++){
		binMessage += bitset<S>(message.c_str()[i]).to_string();
	}// end for

	// Append Padding Bits
	if(binMessage.length() < LENGTH){
		binMessage += '1';

		for(int i = binMessage.length(); i < LENGTH; i++){
			binMessage += '0';
		}// end for
	}// end if


	int m = message.length() << 3;	// size * 8

	// Append Message Length
	bitLength += bitset<64>(m).to_string();

	binMessage += bitLength;	

	return binMessage;

}// end pad_message

/*
* This method turns the binary message representation into 16 32 bit words.
* Params: This method takes in a string, and two arrays as parameters.
* Pre: String array must already be loaded and the message should be in binary.
* Post: none.
*/
void digestMessage(string binMessage, string M[], uint4 X[]){

	// Get 16 32 bit words
	int index = 0;
	for(int i = 0; i < 16; i++){
		for(int j = 0; j < 32; j++){
			M[i] += binMessage.substr()[index];
			index++;
		}// end for
	}// end for

	// string to unsigned int
	for(int i = 0; i < 16; i++){
		stringstream stream(M[i]);
		stream >> X[i];
	}// end for

}// end digestMessage

/*
* This method initializes the array of 64 elements to be used during transformation.
* Params: This method takes in an unsigned int array as a parameter.
* Pre: Array must be initialized.
* Post: none.
*/
void init_array(uint4 T[]){
	long int v;
	// T[i] = abs(sin(i+1) * 2^32)
	// Generate 64 elements of T for transform
	for(int i = 0; i < 64; i++){
		v = sin(i + 1);
		v *= pow(2, 32);
		T[i] = abs(v);
	}// end for	
}// end init_array

/*
* This method performs bitwise operations on three 32 bit words.
* Params: This method takes in three 32 bit words as parameters.
* Pre: all three words must be initialized.
* Post: This method returns one 32 bit word.
*/
uint4 F(uint4 x, uint4 y, uint4 z){
	return ((x & y) | (~x & z));
}// end F

/*
* This method performs bitwise operations on three 32 bit words.
* Params: This method takes in three 32 bit words as parameters.
* Pre: all three words must be initialized.
* Post: This method returns one 32 bit word.
*/
uint4 G(uint4 x, uint4 y, uint4 z){
	return ((x & z) | (y & ~z));
}// end G

/*
* This method performs bitwise operations on three 32 bit words.
* Params: This method takes in three 32 bit words as parameters.
* Pre: all three words must be initialized.
* Post: This method returns one 32 bit word.
*/
uint4 H(uint4 x, uint4 y, uint4 z){
	return (((x ^ y) ^ z));
}// end H

/*
* This method performs bitwise operations on three 32 bit words.
* Params: This method takes in three 32 bit words as parameters.
* Pre: all three words must be initialized.
* Post: This method returns one 32 bit word.
*/
uint4 I(uint4 x, uint4 y, uint4 z){
	return (y ^ (x | ~z));
}// end I

/*
* This method performs the operation a = b + ((a + F(b, c, d) + x[k] + t[i]) << s).
* Params: This method takes in 4 32 bit words, 3 integers, and two arrays.
* Pre: all four words must be initialized, and the two arrays must be loaded.
* Post: none.
*/
void FF(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + F(b, c, d) + x[k] + t[i]) << s);
}// end FF

/*
* This method performs the operation a = b + ((a + G(b, c, d) + x[k] + t[i]) << s).
* Params: This method takes in 4 32 bit words, 3 integers, and two arrays.
* Pre: all four words must be initialized, and the two arrays must be loaded.
* Post: none.
*/
void GG(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + G(b, c, d) + x[k] + t[i]) << s);
}// end GG

/*
* This method performs the operation a = b + ((a + H(b, c, d) + x[k] + t[i]) << s).
* Params: This method takes in 4 32 bit words, 3 integers, and two arrays.
* Pre: all four words must be initialized, and the two arrays must be loaded.
* Post: none.
*/
void HH(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + H(b, c, d) + x[k] + t[i]) << s);

}// end HH

/*
* This method performs the operation a = b + ((a + I(b, c, d) + x[k] + t[i]) << s).
* Params: This method takes in 4 32 bit words, 3 integers, and two arrays.
* Pre: all four words must be initialized, and the two arrays must be loaded.
* Post: none.
*/
void II(uint4 &a, uint4 b, uint4 c, uint4 d, int k, int s, int i, uint4 x[], uint4 t[]){
	a = b + ((a + I(b, c, d) + x[k] + t[i]) << s);
}// end II
