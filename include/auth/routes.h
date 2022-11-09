#ifndef _DILLO_AUTH_ROUTES_H_
#define _DILLO_AUTH_ROUTES_H_

#include "auth/auth.h"
#include "auth/config.h"

#define AUTH_ROUTE_ACTION_SIZE			128
#define AUTH_ROUTE_ROLE_SIZE			128
#define AUTH_ROUTE_PERMISSIONS_SIZE		256

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthRoute {

	DilloAuthType auth_type;
	DilloAuthScope auth_scope;

	int action_len;
	char action[AUTH_ROUTE_ACTION_SIZE];

	int role_len;
	char role[AUTH_ROUTE_ROLE_SIZE];

} AuthRoute;

AUTH_EXPORT void auth_route_delete (void *auth_route_ptr);

AUTH_EXPORT AuthRoute *auth_route_create (void);

AUTH_EXPORT AuthRoute *auth_route_create_action (const char *action);

AUTH_EXPORT AuthRoute *auth_route_create_role (
	const char *action, const char *role
);

AUTH_EXPORT void auth_route_print (const AuthRoute *auth_route);

#ifdef __cplusplus
}
#endif

#endif
