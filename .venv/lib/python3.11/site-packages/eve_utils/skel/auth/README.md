# auth

This module adds authentication to your API

## Settings
| Variable               | Description                                                  | Default                                          |
| ---------------------- | ------------------------------------------------------------ | ------------------------------------------------ |
| ES-AUTH_ADD_BASIC      | When enabled, allows a basic authentication scheme with root/password | No                                               |
| ES-AUTH_ROOT_PASSWORD  | When ES-AUTH_ADD_BASIC is enabled, this is the password the root user uses to gain access to the API. | password                                         |
| ES-AUTH_REALM          | Appears in the `WWW-Authenticate` header in unauthorized requests. | {$project_name}.pointw.com                       |
| ES-AUTH_JWT_DOMAIN     |                                                              | {$project_name}.us.auth0.com                     |
| ES-AUTH_JWT_AUDIENCE   | This is the identifier a client uses when requesting a token from the auth provider.  It is a URI only (identifier only), not an actual URL (i.e. no requests are made to it) | https://pointw.com/{$project_name}               |
| AUTH0_API_AUDIENCE     | When {$project_name} requests a token to use the Auth0 API, this is the audience for the token. | https://{$project_name}.us.auth0.com/api/v2/     |
| AUTH0_API_BASE_URL     | The base of the Auth0 API                                    | https://{$project_name}.us.auth0.com/api/v2      |
| AUTH0_CLAIMS_NAMESPACE | If you configure Auth0 to insert additional claims, use this value as a namespace (prefix). | https://pointw.com/{$project_name}               |
| AUTH0_TOKEN_ENDPOINT   | When {$project_name} needs to call the Auth0 API, it uses this endpoint to request a token. | https://{$project_name}.us.auth0.com/oauth/token |
| AUTH0_CLIENT_ID        | When {$project_name} needs to call the Auth0 API, it uses this client id/secret to authenticate.  These are not the client id/secret of your application. | --your-client-id--                               |
| AUTH0_CLIENT_SECRET    |                                                              | --your-client-secret--                           |

## Configure Auth0

* [Login to Auth0](https://auth0.com/auth/login) with your management credentials
* Create a tenant
  * Name: {$project_name}
    * Used in  `ES-AUTH_JWT_DOMAIN`, `AUTH0_API_AUDIENCE`, `AUTH0_API_BASE_URL`, `AUTH0_TOKEN_ENDPOINT`
  * Logo (optional) 200px x 60px
    (e.g. https://app.cri.com/images/cri-wide.png)
  * Default audience (optional - makes using Postman easier)
* Create Application
  * Logo (optional) 150px x 150px
    (e.g. https://app.cri.com/images/cri150.png)
  * Application Type: Single Page Web Application
  * Token Endpoint Authentication Method: None (default)
  * Application Login URI (optional)
  * Allowed Callback URLs
    * Include https://oauth.pstmn.io/v1/callback for Postman (when enabling Authorize Using Browser)
    * http://localhost:8080, etc.
  * Allowed Logout URLs
    * http://localhost:8080
  * Allowed Web Origins (no paths required - just scheme, domain, [port], wildcard sub-domains allowed)
    * http://localhost:8080
  * Allowed Origins (CORS) (optional)
  * Use defaults for the rest, but read and understand, and consider any changes
  * Decide whether to disable google-oauth2 (in Connections tab of the application)
* Create API
  * Identifier (e.g. https://pointw.com/{$project_name} )
    * use the value you specified in ES-AUTH_JWT_AUDIENCE
  * Signing Algorithm: RS256
  * Allow Skipping User Consent (why doesn't this work?)
* Branding->Universal Login
  * Experience (New or Classic)
  * Sign in screen (Identifier + Password, or Identifier First)
  * Logo (use Tenant logo from above)
  * Colours
  * Further customization
* Cleanup
  * Delete Default App (leave machine to machine app)
  * Delete name-api (Test Application)
* Add users

## Notes on Postman
* EveService APIs need JWTs to authenticate.
* Auth0 creates the JWT but…  
  * it will not give it to the UI unless the UI tells Auth0 the audience, i.e. which API it is going to use the token to access
  * When Auth0 doesn't know the audience, it will issue an opaque token.  The API must use this opaque token and ask Auth0 for the JWT (EveService does not yet do this TODO: ??)
  * Auth0 can be configured with a default audience for convenience (at the tenant level)

* Postman will act as the UI and request a token of Auth0 to access the API - the same way the UI does
  * Use the ClientID (and client secret for Authorization Code) of assigned by Auth0 for the UI application (not machine to machine)
  * if [X] Authorize using browser, tell Auth0 to allow callback URL of https://oauth.pstmn.io/v1/callback

* If using Authorization Code grant type, pass the audience by query string to the Auth URL
  * e.g. https://{$project_name}.us.auth0.com/authorize?audience=https://pointw.com/{$project_name}

* Clear cookies to force login again
  * when in Request window, not collection, it will appear upper right under Send
  * When in collection window, it is at the bottom, above "Get New Access Token"
