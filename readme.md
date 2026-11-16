<picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/veracode/veracode.github.io/aed0a49cd8b08056e6093232a29f49791bf21432/assets/images/veracode-white-hires.svg" height="200" width="200">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/veracode/veracode.github.io/aed0a49cd8b08056e6093232a29f49791bf21432/assets/images/veracode-black-hires.svg" height="200" width="200">
    <img alt="Veracode Logo" src="https://raw.githubusercontent.com/veracode/veracode.github.io/aed0a49cd8b08056e6093232a29f49791bf21432/assets/images/veracode-black-hires.svg" height="200" width="200">
</picture>

# Accessing Veracode APIs with Bruno

## Overview

Using [Veracode APIs](https://docs.veracode.com/r/c_gettingstarted) with Bruno requires initial configuration to accommodate HMAC signing. Below are instructions for getting up and running with Veracode APIs in Bruno.

## Before You Begin

### Generate Token Credentials

If you have not does so, please follow these steps to generate the necessary API Token Credential to use with Bruno.

1. [Generate API credentials](https://docs.veracode.com/r/t_create_api_creds) for your Veracode user.
2. Store the credential information is  a safe place or as a [credential file](https://docs.veracode.com/r/c_configure_api_cred_file) for use with Veracode products.


### Setup Bruno

1. Install Bruno on your machine.
2. Create a Collection.
3. In the **Script** tab paste in the code from [bruno-pre-request-script.js](bruno-pre-request-script.js) and click the save button.
4. Create a new **Environment** for the Veracode platform.
5. Update the following variables as type *secret*
  - *api_id* : (set to your Veracode API ID)
  - *api_key* : (set to your Veracode API Key)
6. Be sure to save
7. In the collection (left nav) add and save a new request. 
   - GET 'https://api.veracode.com/api/authn/v2/users/self'


## Using an OAuth bearer token instead of HMAC

By default the script signs requests with HMAC (see above). To use an OAuth bearer token instead, add these variables to the Bruno environment:

| Variable | Type | Value |
|---|---|---|
| *veracode_auth_type* | plain | `oauth` (`hmac` or unset keeps HMAC) |
| *hostname* | plain | Veracode API base URL including the scheme, e.g. `https://api.veracode.com` |
| *oauth_veracode_client_id* | *secret* | your OAuth client ID |
| *oauth_veracode_client_secret* | *secret* | your OAuth client secret |

`api_id` and `api_key` are not needed in `oauth` mode. The credentials are looked up in the same order as `api_id` and `api_key`: collection environment, global/workspace environment, process env, then secret manager.

How it works:
- The script requests a token from `{{hostname}}/api/authn/v2/oauth2/token` (`client_credentials` grant) and sends `Authorization: Bearer <token>`.
- The token is cached in Bruno runtime variables (memory only) and reused until 60 seconds before it expires. It is fetched again if `hostname` or the client ID changes. If two environments share the same `hostname` and client ID but have different secrets, a token cached from one is reused for the other until it expires or Bruno restarts.
- If the token request fails, the request stops with an error. There is no fallback to HMAC.
- The token is only sent to requests whose URL host matches `hostname`. Requests to other hosts stop with an error.



## License

[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
See the [LICENSE](https://github.com/veracode/.github/blob/main/LICENSE) for details
