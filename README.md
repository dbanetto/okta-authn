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

Get a login session from Okta

 - [~] configuration file for multiple Okta
    - [x] select config file
    - [ ] select config via environment variables
 - [x] Use system's keychain to store password
 - [~] Support MFA prompts
    - [x] WebAuthn / CTAP2
    - [ ] U2F / FIDO / CTAP1
    - [ ] TOTP
    - [ ] Mobile push

### App authentication

Convert the session into an application session

 - [ ] Support SAML app
 - [ ] Support OIDC app
 - [ ] Support app level MFA prompts 

### App support

 - [ ] AWS credential helper
 - [ ] git credential helper
 - [ ] HashiCorp vault
