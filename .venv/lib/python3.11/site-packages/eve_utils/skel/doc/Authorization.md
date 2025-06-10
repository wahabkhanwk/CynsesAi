# Auth0

This repository contains the exports for all tenants in Auth0, along with notes for each.



## Postman

To set up Postman to call `{$project_name}`, use the following values in the OAuth2 authorization type:

```
Token Name:             {$project_name} token
Grant Type:             Authorization Code (With PKCE)
Callback URL:           http://localhost:8000
                          [ ] Authorize using browser
Auth URL:               TODO: add from your configuration
Access Token URL:       TODO: add from your configuration
Client ID:              TODO: add from your configuration
Client Secret:          TODO: add from your configuration
Code Challenge Method:  SHA-256
Code Verifier:
Scope:
State:
Client Authentication:  Send as Basic Auth header
```

TIP: Enable the Postman setting "Retain headers when clicking on links".  This will let you copy the Authorization header.  Set Authorization Type to None, paste the Authorization header, now clicking links will be authorized.  You will have to repeat these steps whenever the token expires.

## Token
The token you obtain after logging in is a JWT with the following payload:

```json
{
  "https://cri.com/ishowroom/claims": {
    "un": "S99111G",
    "dc": "99970",
    "dn": "DC & FC TEST DEALER",
    "ad": "800 CHRYSLER DR.",
    "cy": "AUBURN HILLS",
    "f": "DCZYXTRPJ",
    "st": "MI",
    "pc": "48326757",
    "fn": "Jack",
    "ln": "Frost",
    "ph": "740-1541",
    "pos": "4T",
    "rg": "US"
  },
  "iss": "https://cri-stellantis-dev.us.auth0.com/",
  "sub": "samlp|fake-idp|S99111G",
  "aud": "uri://cri.com/ishowroom-catalog-api",
  "iat": 1636428773,
  "exp": 1636515173,
  "azp": "eKYFw6OKNq0XJesDNL0Xqt9cxKXIluqk",
  "permissions": [
    "multitenant",
    "modify",
    "publish",
    "read"
  ]
}
```



## Claims

The claims with namespace https://cri.com/ishowroom/claims are:

User

* un	username
* fn	first name
* ln	last name
* pos	position code

Dealership

* dc	dealer code
* dn	dealer name
* ad	address
* cy	city
* st	state/province
* pc	zip/postal code
* ph	phone number
* f		franchises
* rg	region - used to enforce tenancy (note: when POSTing with a user that has the multitenant permission, you must specify the "_tenant" field)



## Permissions

read/modify - self evident

publish - with this permission a user can operate the publish/draft/discard affordances of a feature_display

multitenant 

* Without this permission a user can only access resources within her region.  All resources she POSTs automatically sets the "_tenant" field.
* With this permission a user can access all resources across all regions.  When POSTing, the user must set the "_tenant" field, otherwise only users with multitenant can see the resource - even if the resource properly belongs to a region.



## Backdoor

If the `ishowroom-catalog-api` is configured with `ES-AUTH_ADD_BASIC` enabled, then there is an additional scheme available: Basic auth.  This provides a dev/qa backdoor to authenticate without Auth0.



There are four users available this way:

* `root` - equivalent to a user with CRI Admin role, i.e. with multitenant permission (only if `ES-AUTH_ENABLE_ROOT_USER` is also enabled)
* ~~`cm_us` - equivalent to a user with Content Manager role whose region is US~~

* ~~`cm_us_no_publish` - equivalent to a user with Content Manager role whose region is US, but without the publish permission~~
* ~~`cm_ca` - equivalent to a user with Content Manager role whose region is CA~~
* `nvd_ca` - read only user whose region is CA
* `nvd_us` - read only user whose region is US



The default password for each of these users is `password`, and is configurable with ES-AUTH_ROOT_PASSWORD



## Alternate

If you cannot parse the jwt, you can configure a client to fetch the user profile from Auth0 Management API with the following details:

API Audience: https://cri-stellantis-dev.us.auth0.com/api/v2/

(requires some Auth0 setup)

Additonally, for a partial profile see the **domain/collection affordances** section of the ishowroom-catalog-api [README](https://us-east-2.console.aws.amazon.com/codesuite/codecommit/repositories/ishowroom-catalog-api/browse?region=us-east-2)

