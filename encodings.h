#pragma once

#ifdef __cplusplus
extern "C" {

	const char* ToBase2(const char* message, unsigned int length);

	const char* ToBase4(const char* message, unsigned int length);

	const char* ToBase8(const char* message, unsigned int length);

	const char* ToBase16(const char* message, unsigned int length);

	const char* ToBase32RFC4648(const char* message, unsigned int length);

	const char* ToBase36(const char* message, unsigned int length);

	const char* ToBase64(const char* message, unsigned int length);

	const char* ToBase85(const char* message, unsigned int length);

#else
	const char* ToBase2(const char* message, unsigned int length);

	const char* ToBase4(const char* message, unsigned int length);

	const char* ToBase8(const char* message, unsigned int length);

	const char* ToBase16(const char* message, unsigned int length);

	const char* ToBase32RFC4648(const char* message, unsigned int length);

	const char* ToBase36(const char* message, unsigned int length);

	const char* ToBase64(const char* message, unsigned int length);

	const char* ToBase85(const char* message, unsigned int length);

#endif

