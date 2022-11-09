#include <cerver/utils/log.h>

#include "auth/version.h"

// print full libauth version information
void dillo_libauth_version_print_full (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nDillo libauth Version: %s", DILLO_AUTH_VERSION_NAME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Release Date & time: %s - %s", DILLO_AUTH_VERSION_DATE, DILLO_AUTH_VERSION_TIME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Author: %s\n", DILLO_AUTH_VERSION_AUTHOR
	);

}

// print the version id
void dillo_libauth_version_print_version_id (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nDillo libauth Version ID: %s\n", DILLO_AUTH_VERSION
	);

}

// print the version name
void dillo_libauth_version_print_version_name (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nDillo libauth Version: %s\n", DILLO_AUTH_VERSION_NAME
	);

}
