#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <bitset>
#include <math.h>

using namespace std;

const int M = 8;
const int LENGTH = 448;

int main(){

	string message = "Password";
	string binMessage = "";
	//string bin = "";
	cout  << "password: " << message << endl; // take out
	for(int i = 0; i < message.size(); i++){
		binMessage += bitset<M>(message.c_str()[i]).to_string();	// convert string to binary
	}

	cout << "binary password: " << binMessage << endl; // take out

	if(binMessage.size() < LENGTH){
		binMessage += '1';

		for(int i = binMessage.size(); i < LENGTH; i++){
			binMessage += '0';
		}
	}
	cout << "binary password after padding: " << binMessage << endl; // take out

	cout << "size of binMessage: " << binMessage.size() << endl;

}
