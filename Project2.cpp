// Group 2, Genavieve Holmberg, Michael Miller, Nathan Reichert
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <bitset>
#include <math.h>
#include "md5test.cpp"


const int SALTLENGTH = 6;
//const int NUMUSERS = 20;
const string MAGIC = "$";

void addUser();
void verifyPassword();
void saveUser(string userID, string password);
void parseUserInfo(string userInfo[], string info);
bool uniqueID(string userID);
string getUserInfo(string userID);
string generateSaltValue();

int main()
{
   int answer;
   while(answer != 0)
   {
      cout << "\n0 to exit\n1 to add a user\n2 to verify password of a user\n";
      cin >> answer;
      switch(answer)
      {
         case 0:
            break;
         case 1:
            addUser();
            break;
         case 2:
            verifyPassword();
            break;
         default:
            cout << "Answer is invalid, please try again\n";
            break;
      }
   }
   return 0;
}

void addUser()
{
   // get user ID from user
   string userID;
   cout << "enter a unique user ID: ";
   cin >> userID;
   while(!uniqueID(userID))
   {
      cout << "Sorry, that user ID is taken. Please try again\nenter a unique user ID: ";
      cin >> userID;
   }

   // get password from user
   string password, repassword;
   cout << "enter a password: ";
   cin >> password;
   cout << "reenter the password: ";
   cin >> repassword;
   while(password.compare(repassword) != 0)
   {
      cout << "Passwords do not match, try again\n";
      cout << "enter a password: ";
      cin >> password;
      cout << "reenter the password: ";
      cin >> repassword;
   }

   // save user to file
   saveUser(userID, password);
}

void verifyPassword()
{
   string userID, password, enteredHash, pwdline;
   string userInfo[4];
   cout << "Enter the userID: ";
   cin >> userID;
   while(uniqueID(userID))
   {
      cout << "The userID you entered is not in the system, please try again: ";
      cin >> userID;
   }
   cout << "Enter " << userID << " password: ";
   cin >> password;

   // get salt and hash value for the user to be compared to the password entered
   pwdline = getUserInfo(userID);
   parseUserInfo(userInfo, pwdline);

   string salt = userInfo[2];
   string savedHash = userInfo[3];

   enteredHash = md5(salt + password);
   cout << "salt: " << salt << endl;//testing
   cout << "entered hash: " << enteredHash << "\tsaved hash: " << savedHash << endl;//testing

   if(savedHash.compare(enteredHash) == 0)
   {
      cout << "Password verified!\n";
   }
   else
   {
      cout << "Password is incorrect\n";
   }

}

void saveUser(string userID, string password)
{
   string salt, hash;
   salt = generateSaltValue();
   hash = md5(salt+password);
   ofstream pwdfile;
   pwdfile.open("pwdfile.txt", std::ios::app);
   pwdfile << MAGIC << userID << MAGIC << salt << MAGIC << hash << endl;
   pwdfile.close();
   cout << "User saved\n";

}

bool uniqueID(string userID)
{
   ifstream pwdfile;
   string line, ID;
   int pos;
   pwdfile.open("pwdfile.txt");
   while(getline(pwdfile, line))
   {
      pos = line.find(userID);
      if(pos != -1){
        return false;
      }
   } 
   return true;
}

string generateSaltValue()
{
   string salt = "";
   char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  for(int i = 0; i < SALTLENGTH; i++)
    salt += alphanum[rand() % (sizeof(alphanum) - 1)];

  salt[SALTLENGTH] = 0;
  return salt;

}

string getUserInfo(string userID)
{
   ifstream pwdfile;
   string line, ID;
   int pos;
   pwdfile.open("pwdfile.txt");
   while(getline(pwdfile, line))
   {
      pos = line.find(userID);
      if(pos != -1){
        break;
      }
   } 
   return line;
}

void parseUserInfo(string userInfo[], string info){

  string delimiter = MAGIC;
  string token;

  int last = 0, next = 0, i = 0;

  while((next = info.find(delimiter, last)) != -1){ // npos == -1
      token = info.substr(last, next - last);
      userInfo[i] = token;
      last = next + 1;
      i++;
  }
  userInfo[i] = info.substr(last);
}