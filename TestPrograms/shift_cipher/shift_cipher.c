#include "taintgrind.h"
#include <stdio.h>
#include <stdlib.h>

int encrypt(int message, int key) {
	int emessage;
	int temp;
	key = key % 26;
	if (message >= 48 && message <= 57) {
		temp = message + key;
		if (temp > 57) {
			emessage = 48 + (temp - 58);
		}
		else {
			emessage = temp;
		}
	}
	else {
		if (message >= 97 && message <= 123) {
			temp = message + key;
			if (temp > 122) {
				emessage = 97 + (temp - 123);
			}
			else {
				emessage = temp;
			}
		}
		else {
			emessage = message;
		}
	}
	return emessage;
}

int decrypt(int emessage, int key) {
	int dmessage;
	int temp;
	if (emessage >= 48 && emessage <= 57) {
		temp = emessage - key;
		if (temp < 48) {
			dmessage = 58 - (48 - temp);
		}
		else {
			dmessage = temp;
		}
	}
	else {
		if (emessage >= 97 && emessage <= 123) {
			temp = emessage - key;
			if (temp < 97) {
				dmessage = 123 - (97 - temp);
			}
			else {
				dmessage = temp;
			}
		}
		else {
			dmessage = emessage;
		}
	}
	return dmessage;
}

void main(int argc, char **argv) {
	// Turns on printing
	TNT_START_PRINT();

	int a = 100;

	int key = 12;

	//Defines int a as tainted
	TNT_MAKE_MEM_TAINTED_NAMED(&key,4,"key");

	int cipher = encrypt(a, key);

	int plain = decrypt(cipher, key);

	// Turns off printing
	TNT_STOP_PRINT();
}
