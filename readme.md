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
3. In the settings for the collection select the **Auth** tab, select **Digest Auth** from the dropdown, and click the save button.
4. In the **Script** tab paste in the code from [bruno-pre-request-script.js](bruno-pre-request-script.js) and click the save button.
5. Create a new **Environment** for the Veracode platform.
6. Update the following variables as type *secret*
  - *api_id* : (set to your Veracode API ID)
  - *api_key* : (set to your Veracode API Key)
7. Be sure to save
8. In the collection (left nav) add and save a new request. 
   - GET 'https://api.veracode.com/api/authn/v2/users/self'



## License

[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
See the [LICENSE](https://github.com/veracode/.github/blob/main/LICENSE) for details
