#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <math.h>
#include "md5test.cpp"
using namespace std;
const int SALTLENGTH = 6;
const int NUMUSERS = 20;
const string MAGIC = "$";

void gen_salt(char s[]);
void write_to_file(string temp_file, string info);
void gen_passwrdFile(char s[], string outfile);
bool user_verification(string hashedPass, string password, string salt);
string find_user_info(string output);
void parse_user_info(string t[], string info);
 
int main()
{
  srand(time(NULL));

  char saltArr[SALTLENGTH];
  string tokens[4];
  string output = "passwordfile.txt";

  gen_passwrdFile(saltArr, output); // generate password file

  string line = find_user_info(output);

  parse_user_info(tokens, line);

  string UID = tokens[1];
  string salt = tokens[2];
  string hashedPass = tokens[3];


  cout << UID << " " << salt << " " << hashedPass << endl;


  if(user_verification(hashedPass, "password", salt)) // "password" can be user input
    cout << "User verified!" << endl;
  else
    cout << "User not Verified!" << endl;



    return 0;
}


void gen_salt(char s[]){
  char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  for(int i = 0; i < SALTLENGTH; i++)
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

  s[SALTLENGTH] = 0;
}


void gen_passwrdFile(char s[], string outfile){

  ofstream outputFile;
  outputFile.open(outfile);

  for(int i = 0; i < NUMUSERS; i++){

    string UID = "user" + to_string(i);
    string password = "password";

    gen_salt(s);

    string salt = s;

    string saltedPass = salt + password;

    string info = MAGIC + UID + MAGIC + salt + MAGIC + md5(saltedPass);

    outputFile << info << "\n";

  }
  outputFile.close();

}


bool user_verification(string hashedPass, string password, string salt){

    if(hashedPass == md5(salt + password))
      return true;
    else
      return false;
}


string find_user_info(string output){

  ifstream input;
  int pos;
  string line;

  input.open(output);
  if(input.is_open()){
    while(getline(input,line)){
      pos = line.find("user10");
      if(pos != -1){
        break;
      }// end if
    }// end while
  }// end if

  return line;
}// end if

void parse_user_info(string t[], string info){

  string delimiter = MAGIC;
  string token;

  int last = 0, next = 0, i = 0;

  while((next = info.find(delimiter, last)) != -1){ // npos == -1
    token = info.substr(last, next - last);
    t[i] = token;
    last = next + 1;
    i++;
  }
  t[i] = info.substr(last);
}

