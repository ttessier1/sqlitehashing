#include <stdlib.h>
#include "encodings.h"

const char* base2Dictionary = "01";
const char* base4Dictionary = "0123";
const char* base8Dictionary = "01234567";
const char* base16Dictionary = "012356789ABCDEF";
const char* base32DictionaryExtHex =           "0123456789ABCDEFGHIJKLMNOPQRSTUV";
const char* base32DictionaryRFC4648=           "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const char* base32DictionaryZBase32 =          "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const char* base32DictionaryCrockFordBase32 =  "0123456789ABCDEFGHJKMNPQRSTVWXWZ";
const char* base32GeoHash =					   "0123456789bcdefghjkmnpqrstuvwxyz";
const char* base32VideoGame =				   "0123456789BCDEFGHJKMNPQRSTVWZY!.";
const char* base32WordSafe =				   "0123456789BCDEFGHJKMNPQRSTVWZY!.";

const char* base36Dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* base45Dictionary = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

const char* base56Dictionary = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
const char* base58Dictionary = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789";
const char* base62Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const char* base64Dictionary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ;

const char* ToBase2(const char* message, unsigned int length)
{
	char * result;
	unsigned int index = 0;
	unsigned int innerIndex = 0;
	unsigned char bitIndex = 0x80;
	unsigned int resultIndex = 0;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char *)result;
	}
	result = (char*)malloc((length*8)+1);
	if (result != NULL)
	{
		for (index = 0; index < length; index++)
		{
			bitIndex = 0x80; // reset after every index change
			for (innerIndex = 0; innerIndex < 8; innerIndex++)
			{
				if(message[index]& bitIndex)
				{ 
					result[resultIndex] = '1';
				}
				else
				{
					result[resultIndex] = '0';
				}
				resultIndex++;
			}
		}
		result[resultIndex] = '\0';
	}
	return (const char*)result;
}

const char* ToBase4(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase8(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase16(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase32RFC4648(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase36(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase64(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}

const char* ToBase85(const char* message, unsigned int length)
{
	char* result;
	if (message == NULL)
	{
		return NULL;
	}
	if (length == 0)
	{
		result = (char*)malloc(1);
		if (result != NULL)
		{
			*result = '\0';
		}
		return (const char*)result;
	}
	return NULL;
}