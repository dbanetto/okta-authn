use base64::display::Base64Display;
use ctap_hid_fido2::{get_assertion, wink, HidParam};
use tracing::{debug, error, info, warn};

use crate::config;
use serde::{Deserialize, Serialize};

#[tracing::instrument]
pub(crate) async fn authenticate(profile: &config::Profile) -> Result<String, ()> {
    let keys = keyring::Keyring::new("okta-authn", &profile.keyring_name);

    // - check for session
    // - start session
    // - get assert / JWT from app

    let client = reqwest::Client::new();
    let res = client
        .post(format!("https://{}/api/v1/authn", profile.domain))
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "username": profile.username,
                "password": keys.get_password().map_err(|err| {
                    error!("Error while creating keyring: {}", err);
                })?,
                "options": {
                    "multiOptionalFactorEnroll": false,
                    "warnBeforePasswordExpired": false
                }
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|err| {
            error!("Error while creating keyring: {}", err);
            ()
        })?;

    let response: AuthnResponse = serde_json::from_slice(&res.bytes().await.map_err(|err| {
        error!("Failed to read bytes of response: {}", err);
    })?)
    .map_err(|err| {
        error!("Failed to prase response: {}", err);
    })?;

    info!("got back {:?}", response);

    return match response.status.as_str() {
        "MFA_REQUIRED" => handle_mfa(&response, profile).await,
        "AUTHENTICATED" => Ok(response.access_token.unwrap()),
        _ => unimplemented!(),
    };
}

async fn handle_mfa(authn: &AuthnResponse, profile: &config::Profile) -> Result<String, ()> {
    debug!("handling mfa request");

    info!("Going through factors");
    let fido_factor = authn
        .embedded
        .factors
        .iter()
        .filter(|f| f.factor_type == "webauthn" && f.provider == "FIDO" && f.vendor_name == "FIDO")
        .next()
        .unwrap();

    debug!("Got factor {:?}", fido_factor);

    let client = reqwest::Client::new();
    let res = client
        .post(&fido_factor.links.verify.as_ref().unwrap().href)
        .header("Content-Type", "application/json")
        .body(
            serde_json::json!({
                "stateToken": authn.state_token.as_ref().unwrap(),
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|err| {
            error!("Error while creating keyring: {}", err);
            ()
        })?;

    let text = res.text().await.map_err(|err| {
        error!("error reading response: {}", err);
    })?;

    let response: MfaChallenge = serde_json::from_slice(&text.as_bytes())
    .map_err(|err| {
        error!("Failed to prase response: {}\n{}", err, text);
    })?;

    debug!("factor {:?}", response);

    // TODO u2f chanallenge
    //  - get a HidParm
    //  - form challenge
    //  - get relay party id
    //  - PIN ?
    let assertion = u2f_assertion(&profile, &response).await.map_err(|_| {
        error!("Failed to get an assertion");
    })?;

    // TODO give it back to Okta

    Ok("".to_owned())
}

#[tracing::instrument]
async fn u2f_assertion(profile: &config::Profile, challenge: &MfaChallenge) -> Result<(), ()> {
    use ctap_hid_fido2::*;

    let mut hid_params: Vec<HidParam> = vec![];
    for (name, hid) in get_fidokey_devices() {
        debug!("Found hid {} ({}:{})", name, hid.vid, hid.pid);
        hid_params.push(hid);
    }

    // wink(&hid_params).map_err(|err| {
    //     error!("Failed to wink: {}", err);
    // })?;

    let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge.embedded.factor.embedded.challenge.challenge,
            "clientExtensions": challenge.embedded.factor.embedded.challenge.extensions,
            "hashAlgorithm": "SHA-256",
            "origin": ("https://".to_owned() + &profile.domain),
        }).to_string();

    let assertion = get_assertion(
        &hid_params,
        // rpid
        &profile.domain,
        // challenge
        // &websafe_decode(&challenge.embedded.factor.embedded.challenge.challenge)?,
        &client_data.as_bytes(),
        // credential id
        &websafe_decode(&challenge.embedded.factor.profile.credential_id)?,
        None,
    )
    .map_err(|err| {
        error!("Failed to get an assertion: {}", err);
    })?;

    debug!("Got assert back with {}", assertion);

    let request = serde_json::json!({
        "stateToken": challenge.state_token,
        "authenticatorData": base64::encode_config(assertion.auth_data, base64::STANDARD),
        "clientData": base64::encode_config(client_data.as_bytes(), base64::STANDARD),
        "signatureData": base64::encode_config(assertion.signature, base64::STANDARD),
    });

    debug!("sending {}", request);

    let client = reqwest::Client::new();
    let res = client
        .post(&challenge.links.next.as_ref().unwrap().href)
        .header("Content-Type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .map_err(|err| {
            error!("Error while creating keyring: {}", err);
            ()
        })?;

    let response: serde_json::Value =
        serde_json::from_slice(&res.bytes().await.map_err(|err| {
            error!("Failed to read response: {}", err);
        })?)
        .map_err(|err| {
            error!("Failed to prase response: {}", err);
        })?;

    debug!("challenege {:?}", response);

    Ok(())
}

fn websafe_decode(input: &str) -> Result<Vec<u8>, ()> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD).map_err(|err| {
        error!("error while decoding {} id: {}", input, err);
    })
}

// The structs below generated using
// https://transform.tools/json-to-rust-serde

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthnResponse {
    pub access_token: Option<String>,
    pub state_token: Option<String>,
    pub expires_at: String,
    pub status: String,
    #[serde(rename = "_embedded")]
    pub embedded: AuthNEmbedded,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthNEmbedded {
    pub user: User,
    pub factor_types: Vec<FactorType>,
    pub factors: Vec<Factor>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub password_changed: String,
    pub profile: Profile,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub login: String,
    pub first_name: String,
    pub last_name: String,
    pub locale: String,
    pub time_zone: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorType {
    pub factor_type: String,
    #[serde(rename = "_links")]
    pub links: Links,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Links {
    pub next: Option<LinkHint>,
    pub verify: Option<LinkHint>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hints {
    pub allow: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Factor {
    pub id: String,
    pub factor_type: String,
    pub provider: String,
    pub vendor_name: String,
    pub profile: FactorProfile,
    #[serde(rename = "_links")]
    pub links: Links,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorProfile {
    pub credential_id: Option<String>,
    pub device_type: Option<String>,
    #[serde(default)]
    pub keys: Vec<Key>,
    pub name: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub question: Option<String>,
    pub question_text: Option<String>,
    pub app_id: Option<serde_json::Value>,
    pub authenticator_name: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub kid: String,
    pub e: String,
    pub n: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkHint {
    pub name: Option<String>,
    pub href: String,
    pub hints: Hints,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallenge {
    pub state_token: String,
    pub expires_at: String,
    pub status: String,
    pub factor_result: String,
    pub challenge_type: String,
    #[serde(rename = "_embedded")]
    pub embedded: EmbeddedProfile,
    #[serde(rename = "_links")]
    pub links: Links,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedProfile {
    pub user: User,
    pub factor: FactorChallenge,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorChallenge {
    pub id: String,
    pub factor_type: String,
    pub provider: String,
    pub vendor_name: String,
    pub profile: FidoProfile,
    #[serde(rename = "_embedded")]
    pub embedded: EmbeddedChallenge,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FidoProfile {
    pub credential_id: String,
    pub app_id: Option<String>,
    pub version: serde_json::Value,
    pub authenticator_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedChallenge {
    pub challenge: Challenge,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub challenge: String,
    pub user_verification: String,
    pub extensions: Extensions,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Extensions {
    pub appid: Option<String>,
}
