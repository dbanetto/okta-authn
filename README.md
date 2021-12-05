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

 - [~] configuration file for multiple Okta
    - [x] select config file
    - [ ] select config via environment variables
 - [x] Use system's keychain to store password
 - [~] Support MFA prompts
    - [x] FIDO2
    - [ ] TOTP
    - [ ] Mobile push

## App authentication

 - [ ] Support SAML app
 - [ ] Support OIDC app
 - [ ] Support app level MFA prompts 
