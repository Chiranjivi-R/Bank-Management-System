📘 Bank Management System (C Project)

A simple bank management system written in C that supports Manager and Customer operations with secure login, account management, and transaction tracking.

🚀 Features
👨‍💼 Manager

Add accounts

Modify accounts

Delete accounts

Search and list accounts

Secure manager login

👤 Customer

Login using Account Number + PIN

Check account information

Deposit / Withdraw money

View transaction history

📄 Data Storage

Accounts stored in BankAcc.dat

Manager credentials stored in Manager.dat

All transactions saved in transactions.dat

🛠️ How to Compile (Windows / VS Code)
Compile:
gcc -std=c99 -Wall -Wextra BankSystem.c -o BankSystem.exe
gcc -std=c99 -Wall -Wextra ManagerSetup.c -o ManagerSetup.exe

Set Manager credentials:
.\ManagerSetup.exe

Run the Bank System:
.\BankSystem.exe

📦 Files Overview
File	Purpose
BankSystem.c	Main banking application (Manager & Customer)
ManagerSetup.c	Creates Manager ID & Password
BankAcc.dat	Stores all account details
Manager.dat	Stores hashed Manager password
transactions.dat	Stores all customer transactions
👨‍💻 Author

Chiranjivi R
