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
using namespace std;

const int SALTLENGTH = 6;
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
   //menu
   int answer = 1;
   while(answer != 0)
   {
      cout << "\n0 to exit\n1 to add a user\n2 to verify password of a user\n";
      cin >> answer;
      switch(answer)
      {
         case 0:
            break;
         case 1:
            addUser(); // add user and their password to the password file
            break;
         case 2:
            verifyPassword(); // verify password of a user
            break;
         default:
            cout << "Answer is invalid, please try again\n";
            break;
      }
   }
   return 0;
}

/*
* Adds a username and password (after going through MD5) to the password file.
* Params: None.
* Pre: None.
* Post: None.
*/
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

/*
* Verifies a user's password.
* Params: None.
* Pre: None.
* Post: None.
*/
void verifyPassword()
{
   string userID, password, enteredHash, pwdline;
   string userInfo[4];

   // get user who wants to verify their password
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
   // extract salt and hash values from string above
   parseUserInfo(userInfo, pwdline);

   // seperate the salt and hash values
   string salt = userInfo[2];
   string savedHash = userInfo[3];

   // put the entered password trough MD5 for comparison
   enteredHash = md5(salt+password);

   // tell user if the password is the same or not
   if(savedHash.compare(enteredHash) == 0)
   {
      cout << "Password verified!\n";
   }
   else
   {
      cout << "Password is incorrect\n";
   }

}

/*
* Saves user, salt, and password in password file. Runs MD5 on password plus a salt value
* Params: two strings, one is the user's ID and the other is the user's password.
* Pre: None.
* Post: None.
*/
void saveUser(string userID, string password)
{
   string salt, hash;
   salt = generateSaltValue(); // get random salt value
   hash = md5(salt+password); // run the password plus salt value through MD5
   ofstream pwdfile;
   pwdfile.open("pwdfile.txt", std::ios::app); // open password file in append mode
   pwdfile << MAGIC << userID << MAGIC << salt << MAGIC << hash << "\n"; // write the user ID, salt value, and hashed password to password file with a delimiter between each. 
   pwdfile.close();
   cout << "User saved\n";

}

/*
* Checks if a userID has been used by a different user before.
* Params: string which holds a userID
* Pre: None.
* Post: Returns true if the user ID is not in the password file, returns false if it is in the password file.
*/
bool uniqueID(string userID)
{
   ifstream pwdfile;
   string line, ID;
   int pos;
   pwdfile.open("pwdfile.txt"); // open password file
   while(getline(pwdfile, line)) // while there are more saved users
   {
      pos = line.find(userID); // check if userID is on line, if found, it will return the position in the file
      if(pos != -1){ // if found
        return false; // return false
      }
   } 
   return true; // userID is not in file, userID is uniqure, return true
}

/*
* Generates a 48 bit salt value.
* Params: None.
* Pre: None.
* Post: Returns a random salt value.
*/
string generateSaltValue()
{
   string salt = "";
   char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"; // all possible characters in the salt value

  for(int i = 0; i < SALTLENGTH; i++)
    salt += alphanum[rand() % (sizeof(alphanum) - 1)]; // pick one of the characters at random and append it to the salt value

  salt[SALTLENGTH] = 0;
  return salt;

}

/*
* Finds user's userID, salt value, and hashed password in the password file
* Params: users userID as a string.
* Pre: User is in the password file, otherwise string returned is empty.
* Post: Returns user's userID, salt value, and hashed password.
*/
string getUserInfo(string userID)
{
   ifstream pwdfile;
   string line = "", ID;
   int pos;
   pwdfile.open("pwdfile.txt");
   while(getline(pwdfile, line)) // get next line in file
   {
      pos = line.find(userID); // find user in line
      if(pos != -1){ // if found break out of loop
        break;
      }
   } 
   return line;
}

/*
* Spilts up string line into the userID, salt value, and hashed password
* Params: array to hold data extracted and string line which holds all the data.
* Pre: None.
* Post: None.
*/
void parseUserInfo(string userInfo[], string info){

  string delimiter = MAGIC;
  string token;

  int last = 0, next = 0, i = 0;

  while((next = info.find(delimiter, last)) != -1){ // npos == -1
      token = info.substr(last, next - last); // extract data
      userInfo[i] = token; // put data into array
      last = next + 1; // increment last
      i++;
  }
  userInfo[i] = info.substr(last);
}