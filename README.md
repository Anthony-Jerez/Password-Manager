# Password-Manager

**Password Manager** is a fully functional command line-based application developed in C that allows users to manage and store their login credentials securely. 

## Features
The following functionality is provided:

- [x] Implementation of a login system to support multiple users 
- [x] Users can store, modify, view, and delete their login credentials 
- [x] Passwords are stored securely in their encrypted form using XOR encryption
- [x] User information is sorted according to usage rate to ensure faster retrieval time of user data
- [x] Randomly generate a secure password

## Upcoming Features
1) Two-factor authentication
2) Recovery option for forgotten passwords

## Execution Instruction
First, create two txt files. One will be used to store the master usernames and encrypted master passwords while the other will be used to store the keys along with master usernames. The keys will be used to perform XOR on the encrypted password to yield the user's actual password. Each piece of user information will be stored in the form of space-separated data. Once this is done, to run the program, two command line arguments must be provided in the following order: Data.txt DataKeys.txt. The Data.txt will contain the master login credentials while the DataKeys.txt will contain the keys and master usernames. Upon creating an account, a new txt file will be generated to enable users to store their personal login credentials. 

## License

    Copyright 2023 Anthony Jerez

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
