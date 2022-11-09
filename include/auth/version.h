#ifndef _DILLO_AUTH_VERSION_H_
#define _DILLO_AUTH_VERSION_H_

#include "auth/config.h"

#define DILLO_AUTH_VERSION			"0.1"
#define DILLO_AUTH_VERSION_NAME		"Version 0.1"
#define DILLO_AUTH_VERSION_DATE		"09/11/2022"
#define DILLO_AUTH_VERSION_TIME		"15:01 CST"
#define DILLO_AUTH_VERSION_AUTHOR	"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

// print full dillo libauth version information
AUTH_PUBLIC void dillo_libauth_version_print_full (void);

// print the version id
AUTH_PUBLIC void dillo_libauth_version_print_version_id (void);

// print the version name
AUTH_PUBLIC void dillo_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif
