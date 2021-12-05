# okta-authn CLI

## Goal

The goal of this project is to securely generate Okta assertions that can be 
use for other services.

The authentication to Okta must be able to support MFA & securely stores passwords 
required to access Okta

The main services to try against are
 * HashiCorp vault as OIDC / SAML
 * AWS OIDC / SAML providers


## Features

### Login

 - [ ] configuration file for multiple Okta
    - [ ] select config file
    - [ ] select config via environment variables
 - [ ] Use system's keychain to store password
 - [ ] Support MFA prompts
    - [ ] FIDO2
    - [ ] TOTP
    - [ ] Mobile push

## App authneticate


