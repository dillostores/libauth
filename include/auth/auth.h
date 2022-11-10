#ifndef _DILLO_AUTH_H_
#define _DILLO_AUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/token.h"
#include "auth/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

#define DILLO_AUTH_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  TOKEN,      		Token)			\
	XX(2,  ACTION,      	Action)			\
	XX(3,  ROLE,  			Role)			\
	XX(4,  SERVICE,			Service)		\
	XX(5,  PERMISSIONS,		Permissions)	\
	XX(6,  MULTIPLE,		Multiple)		\
	XX(7,  COMPLETE,		Complete)

typedef enum DilloAuthType {

	#define XX(num, name, string) DILLO_AUTH_TYPE_##name = num,
	DILLO_AUTH_TYPE_MAP(XX)
	#undef XX

} DilloAuthType;

AUTH_PUBLIC const char *dillo_auth_type_to_string (
	const DilloAuthType type
);

#define DILLO_AUTH_SCOPE_MAP(XX)	\
	XX(0,  NONE,      	None)			\
	XX(1,  SINGLE,      Single)			\
	XX(2,  MANAGEMENT,  Management)

typedef enum DilloAuthScope {

	#define XX(num, name, string) DILLO_AUTH_SCOPE_##name = num,
	DILLO_AUTH_SCOPE_MAP(XX)
	#undef XX

} DilloAuthScope;

AUTH_PUBLIC const char *dillo_auth_scope_to_string (
	const DilloAuthScope scope
);

typedef struct DilloAuth {

	DilloAuthType type;
	DilloAuthScope scope;

	char service[AUTH_ID_SIZE];

	bool super_admin;

	AuthToken token;

	int64_t mask;

} DilloAuth;

AUTH_PUBLIC void dillo_auth_delete (void *auth_ptr);

AUTH_EXPORT const DilloAuthType dillo_auth_get_type (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const DilloAuthScope dillo_auth_get_scope (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const bool dillo_auth_get_admin (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_id (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const DilloTokenType dillo_auth_get_token_type (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_organization (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_permissions (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_role (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_user (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const char *dillo_auth_get_token_username (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT const int64_t dillo_auth_get_mask (
	const DilloAuth *dillo_auth
);

AUTH_PUBLIC DilloAuth *dillo_auth_create (
	const DilloAuthType type
);

AUTH_EXPORT void dillo_auth_print_token (
	const DilloAuth *dillo_auth
);

AUTH_EXPORT unsigned int dillo_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif
