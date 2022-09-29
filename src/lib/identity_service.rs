mod cognito_identity_provider;
mod congnito_identity_provider_config;

pub use cognito_identity_provider::*;
pub use congnito_identity_provider_config::*;

use super::*;
use async_trait::async_trait;
use aws_config;
use serde::Serialize;

#[derive(Serialize)]
pub struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Serialize, PartialEq, Debug)]
pub enum IdentityProviderErrKind {
    #[serde(rename = "unknown")]
    Unknown,

    #[serde(rename = "username-exists")]
    UsernameExists,

    #[serde(rename = "new-password-needed")]
    NewPasswordNeeded,

    #[serde(rename = "unknown-auth-challenge")]
    UnknownAuthChallenge,

    #[serde(rename = "incorrect-credentials")]
    IncorrectCredentials,
}

#[async_trait]
/// Provides identity and authentication capabilities
pub trait IdentityProvider {
    /// Creates a new user.
    ///
    /// # Arguments
    ///
    /// * `email` - The email of the new user
    /// * `username` - The username of the new user
    ///
    /// # Returns
    /// The created user's username
    ///
    async fn signup(
        &self,
        email: &str,
        username: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>>;

    /// Attempts a login
    ///
    /// # Arguments
    ///
    /// * `username` - The email or username of the user
    /// * `password`
    ///
    /// # Returns
    ///
    /// Returns a login response containing the refresh_token and an access_token
    async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginResponse, Whoops<IdentityProviderErrKind>>;

    /// Triggers a forgot password flow.
    ///
    /// When invoked a recovery code will be sent to a user.
    /// Using the recovery code `confirm_forgot_password` can be called
    ///
    /// # Arguments
    ///
    /// `username` - username or email of the user
    ///
    /// # Returns
    ///
    /// User's username
    async fn forgot_password(
        &self,
        username: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>>;

    /// Confirms a password is forgotten and sets a new password.
    ///
    /// # Arguments
    ///
    /// `username`  - username or email of the user
    /// `new_password` - the new password to be set
    /// `confimation_code` - the confirmation code recieved by
    /// the user when invoking `forgot_password`
    ///
    /// # Returns
    ///
    /// User's username
    async fn confirm_forgot_password(
        &self,
        username: &str,
        new_password: &str,
        confirmation_code: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>>;

    /// Replaces the user's password with a new password.
    ///
    /// # Arguments
    ///
    /// `username` - username or email of the user
    /// `old_password` - the user's current password
    /// `new_password` - the intended password to be used
    ///
    /// # Returns
    /// User's username
    async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>>;
}
