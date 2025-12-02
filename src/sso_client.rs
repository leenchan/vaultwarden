use std::{borrow::Cow, sync::LazyLock, time::Duration};

use mini_moka::sync::Cache;
use openidconnect::{core::*, reqwest, *};
use regex::Regex;
use url::Url;

use crate::{
    api::{ApiResult, EmptyResult},
    db::models::SsoNonce,
    error::Error,
    sso::{OIDCCode, OIDCState},
    CONFIG,
};

static CLIENT_CACHE_KEY: LazyLock<String> = LazyLock::new(|| "sso-client".to_string());
static CLIENT_CACHE: LazyLock<Cache<String, Client>> = LazyLock::new(|| {
    Cache::builder().max_capacity(1).time_to_live(Duration::from_secs(CONFIG.sso_client_cache_expiration())).build()
});

/// OpenID Connect Core client.
pub type CustomClient = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointSet,
>;

#[derive(Clone)]
pub struct Client {
    pub http_client: reqwest::Client,
    pub core_client: CustomClient,
}

impl Client {
    // Call the OpenId discovery endpoint to retrieve configuration
    async fn _get_client() -> ApiResult<Self> {
        let client_id = ClientId::new(CONFIG.sso_client_id());
        let client_secret = ClientSecret::new(CONFIG.sso_client_secret());

        let issuer_url = CONFIG.sso_issuer_url()?;

        let http_client = match reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build() {
            Err(err) => err!(format!("Failed to build http client: {err}")),
            Ok(client) => client,
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
            Err(err) => err!(format!("Failed to discover OpenID provider: {err}")),
            Ok(metadata) => metadata,
        };

        let base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

        let token_uri = match base_client.token_uri() {
            Some(uri) => uri.clone(),
            None => err!("Failed to discover token_url, cannot proceed"),
        };

        let user_info_url = match base_client.user_info_url() {
            Some(url) => url.clone(),
            None => err!("Failed to discover user_info url, cannot proceed"),
        };

        let core_client = base_client
            .set_redirect_uri(CONFIG.sso_redirect_url()?)
            .set_token_uri(token_uri)
            .set_user_info_url(user_info_url);

        Ok(Client {
            http_client,
            core_client,
        })
    }

    // Simple cache to prevent recalling the discovery endpoint each time
    pub async fn cached() -> ApiResult<Self> {
        if CONFIG.sso_client_cache_expiration() > 0 {
            match CLIENT_CACHE.get(&*CLIENT_CACHE_KEY) {
                Some(client) => Ok(client),
                None => Self::_get_client().await.inspect(|client| {
                    debug!("Inserting new client in cache");
                    CLIENT_CACHE.insert(CLIENT_CACHE_KEY.clone(), client.clone());
                }),
            }
        } else {
            Self::_get_client().await
        }
    }

    pub fn invalidate() {
        if CONFIG.sso_client_cache_expiration() > 0 {
            CLIENT_CACHE.invalidate(&*CLIENT_CACHE_KEY);
        }
    }

    // The `state` is encoded using base64 to ensure no issue with providers (It contains the Organization identifier).
    pub async fn authorize_url(state: OIDCState, redirect_uri: String) -> ApiResult<(Url, SsoNonce)> {
        let scopes = CONFIG.sso_scopes_vec().into_iter().map(Scope::new);
        let base64_state = data_encoding::BASE64.encode(state.to_string().as_bytes());

        let client = Self::cached().await?;
        let mut auth_req = client
            .core_client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                || CsrfToken::new(base64_state),
                Nonce::new_random,
            )
            .add_scopes(scopes)
            .add_extra_params(CONFIG.sso_authorize_extra_params_vec());

        let verifier = if CONFIG.sso_pkce() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            auth_req = auth_req.set_pkce_challenge(pkce_challenge);
            Some(pkce_verifier.into_secret())
        } else {
            None
        };

        let (auth_url, _, nonce) = auth_req.url();
        Ok((auth_url, SsoNonce::new(state, nonce.secret().clone(), verifier, redirect_uri)))
    }

    pub async fn exchange_code(
        &self,
        code: OIDCCode,
        nonce: SsoNonce,
    ) -> ApiResult<(
        StandardTokenResponse<
            IdTokenFields<
                EmptyAdditionalClaims,
                EmptyExtraTokenFields,
                CoreGenderClaim,
                CoreJweContentEncryptionAlgorithm,
                CoreJwsSigningAlgorithm,
            >,
            CoreTokenType,
        >,
        IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
    )> {
        let oidc_code = AuthorizationCode::new(code.to_string());

        let mut exchange = self.core_client.exchange_code(oidc_code);

        if CONFIG.sso_pkce() {
            match nonce.verifier {
                None => err!(format!("Missing verifier in the DB nonce table")),
                Some(secret) => exchange = exchange.set_pkce_verifier(PkceCodeVerifier::new(secret)),
            }
        }

        match exchange.request_async(&self.http_client).await {
            Err(err) => err!(format!("Failed to contact token endpoint: {:?}", err)),
            Ok(token_response) => {
                let oidc_nonce = Nonce::new(nonce.nonce);

                let id_token = match token_response.extra_fields().id_token() {
                    None => err!("Token response did not contain an id_token"),
                    Some(token) => token,
                };

                if CONFIG.sso_debug_tokens() {
                    debug!("Id token: {}", id_token.to_string());
                    debug!("Access token: {}", token_response.access_token().secret());
                    debug!("Refresh token: {:?}", token_response.refresh_token().map(|t| t.secret()));
                    debug!("Expiration time: {:?}", token_response.expires_in());
                }

                let id_claims = match id_token.claims(&self.vw_id_token_verifier(), &oidc_nonce) {
                    Ok(claims) => claims.clone(),
                    Err(err) => {
                        Self::invalidate();
                        err!(format!("Could not read id_token claims, {err}"));
                    }
                };

                Ok((token_response, id_claims))
            }
        }
    }

    pub async fn user_info(&self, access_token: AccessToken) -> ApiResult<CoreUserInfoClaims> {
        match self.core_client.user_info(access_token, None).request_async(&self.http_client).await {
            Err(err) => err!(format!("Request to user_info endpoint failed: {err}")),
            Ok(user_info) => Ok(user_info),
        }
    }

    pub async fn check_validity(access_token: String) -> EmptyResult {
        let client = Client::cached().await?;
        match client.user_info(AccessToken::new(access_token)).await {
            Err(err) => {
                err_silent!(format!("Failed to retrieve user info, token has probably been invalidated: {err}"))
            }
            Ok(_) => Ok(()),
        }
    }

    pub fn vw_id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
        let mut verifier = self.core_client.id_token_verifier();
        if let Some(regex_str) = CONFIG.sso_audience_trusted() {
            match Regex::new(&regex_str) {
                Ok(regex) => {
                    verifier = verifier.set_other_audience_verifier_fn(move |aud| regex.is_match(aud));
                }
                Err(err) => {
                    error!("Failed to parse SSO_AUDIENCE_TRUSTED={regex_str} regex: {err}");
                }
            }
        }
        verifier
    }

    pub async fn exchange_refresh_token(
        refresh_token: String,
    ) -> ApiResult<(Option<String>, String, Option<Duration>)> {
        let rt = RefreshToken::new(refresh_token);

        let client = Client::cached().await?;
        let token_response =
            match client.core_client.exchange_refresh_token(&rt).request_async(&client.http_client).await {
                Err(err) => err!(format!("Request to exchange_refresh_token endpoint failed: {:?}", err)),
                Ok(token_response) => token_response,
            };

        Ok((
            token_response.refresh_token().map(|token| token.secret().clone()),
            token_response.access_token().secret().clone(),
            token_response.expires_in(),
        ))
    }

    /// Logout from Keycloak by revoking the refresh token
    /// This calls the Keycloak logout endpoint to invalidate the session
    pub async fn logout(refresh_token: String) -> EmptyResult {
        let issuer_url = CONFIG.sso_issuer_url()?;
        let logout_url = format!("{}/protocol/openid-connect/logout", issuer_url.as_str());

        let client_id = CONFIG.sso_client_id();
        let client_secret = CONFIG.sso_client_secret();

        // Build the logout request
        let mut params = std::collections::HashMap::new();
        params.insert("refresh_token", refresh_token);
        params.insert("client_id", client_id);
        params.insert("client_secret", client_secret);

        let client = Self::cached().await?;
        match client
            .http_client
            .post(&logout_url)
            .form(&params)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    debug!("Successfully logged out from Keycloak");
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    warn!("Keycloak logout returned status {}: {}", status, body);
                    // Don't fail logout if Keycloak logout fails - user is already logged out locally
                    Ok(())
                }
            }
            Err(e) => {
                warn!("Failed to call Keycloak logout endpoint: {}", e);
                // Don't fail logout if Keycloak logout fails - user is already logged out locally
                Ok(())
            }
        }
    }

    /// Logout user from Keycloak by email using Admin API
    /// This finds the user by email and logs out all their sessions
    pub async fn logout_by_email(email: &str) -> EmptyResult {
        let issuer_url = CONFIG.sso_issuer_url()?;
        
        // Get admin API base URL (format: https://keycloak.example.com/admin/realms/{realm})
        let admin_base_url = extract_admin_base_url(&issuer_url)?;
        
        let client_id = CONFIG.sso_client_id();
        let client_secret = CONFIG.sso_client_secret();

        // Get admin access token using client credentials grant
        let admin_token = get_admin_token(&issuer_url, &client_id, &client_secret).await?;

        let client = Self::cached().await?;

        // Find user by email
        let user_id = find_user_by_email(&client.http_client, &admin_base_url, &admin_token, email).await?;

        // Logout user from all sessions
        logout_user_sessions(&client.http_client, &admin_base_url, &admin_token, &user_id).await?;

        Ok(())
    }
}

/// Extract realm name from Keycloak issuer URL
/// Format: https://keycloak.example.com/realms/{realm}
fn extract_realm_from_issuer(issuer_url: &str) -> ApiResult<String> {
    let url = Url::parse(issuer_url).map_err(|e| Error::new_msg(format!("Failed to parse issuer URL: {}", e)))?;
    let path = url.path();
    
    // Extract realm from path like "/realms/{realm}"
    if let Some(realm_start) = path.rfind("/realms/") {
        let realm_part = &path[realm_start + 8..]; // 8 = len("/realms/")
        if realm_part.is_empty() {
            err!("Realm name is empty in issuer URL");
        }
        Ok(realm_part.to_string())
    } else {
        err!("Failed to extract realm from issuer URL: {}", issuer_url)
    }
}

/// Extract admin API base URL from issuer URL
/// Format: https://keycloak.example.com/admin/realms/{realm}
fn extract_admin_base_url(issuer_url: &str) -> ApiResult<String> {
    let _url = Url::parse(issuer_url).map_err(|e| Error::new_msg(format!("Failed to parse issuer URL: {}", e)))?;
    let realm = extract_realm_from_issuer(issuer_url)?;
    
    // Replace "/realms/{realm}" with "/admin/realms/{realm}"
    let admin_url = issuer_url.replace(&format!("/realms/{}", realm), &format!("/admin/realms/{}", realm));
    Ok(admin_url)
}

/// Get admin access token using client credentials grant
async fn get_admin_token(issuer_url: &str, client_id: &str, client_secret: &str) -> ApiResult<String> {
    let token_url = format!("{}/protocol/openid-connect/token", issuer_url);
    
    let client = reqwest::Client::new();
    let mut params = std::collections::HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);

    let response = client
        .post(&token_url)
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        err!(format!("Failed to get admin token: {}", body));
    }

    let json: serde_json::Value = response.json().await?;
    let access_token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::new_msg("No access_token in response"))?;

    Ok(access_token.to_string())
}

/// Find user by email using Keycloak Admin API
async fn find_user_by_email(
    http_client: &reqwest::Client,
    admin_base_url: &str,
    admin_token: &str,
    email: &str,
) -> ApiResult<String> {
    // Build URL with query parameter
    let mut url = Url::parse(admin_base_url).map_err(|e| Error::new_msg(format!("Failed to parse admin base URL: {}", e)))?;
    url.path_segments_mut()
        .map_err(|_| Error::new_msg("Invalid admin base URL"))?
        .push("users");
    url.query_pairs_mut().append_pair("email", email);
    let users_url = url.to_string();

    let response = http_client
        .get(&users_url)
        .header("Authorization", format!("Bearer {}", admin_token))
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        err!(format!("Failed to find user by email: {}", body));
    }

    let users: Vec<serde_json::Value> = response.json().await?;
    
    if users.is_empty() {
        err!(format!("User with email {} not found in Keycloak", email));
    }

    // Get the first user's ID
    let user_id = users[0]
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::new_msg("No user ID in response"))?;

    Ok(user_id.to_string())
}

/// Logout user from all sessions using Keycloak Admin API
async fn logout_user_sessions(
    http_client: &reqwest::Client,
    admin_base_url: &str,
    admin_token: &str,
    user_id: &str,
) -> EmptyResult {
    let logout_url = format!("{}/users/{}/logout", admin_base_url, user_id);

    let response = http_client
        .post(&logout_url)
        .header("Authorization", format!("Bearer {}", admin_token))
        .header("Content-Type", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        debug!("Successfully logged out user {} from all Keycloak sessions", user_id);
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        warn!("Keycloak logout returned status {}: {}", status, body);
        // Don't fail logout if Keycloak logout fails
        Ok(())
    }
}

trait AuthorizationRequestExt<'a> {
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(self, params: Vec<(N, V)>) -> Self;
}

impl<'a, AD: AuthDisplay, P: AuthPrompt, RT: ResponseType> AuthorizationRequestExt<'a>
    for AuthorizationRequest<'a, AD, P, RT>
{
    fn add_extra_params<N: Into<Cow<'a, str>>, V: Into<Cow<'a, str>>>(mut self, params: Vec<(N, V)>) -> Self {
        for (key, value) in params {
            self = self.add_extra_param(key, value);
        }
        self
    }
}
