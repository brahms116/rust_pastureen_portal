use super::*;
use async_trait::async_trait;
use aws_config;
use aws_sdk_cognitoidentityprovider::Client;

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
    async fn signup(email: &str, username: &str) -> Result<String>;

    /// Attempts a login
    ///
    /// # Arguments
    ///
    /// * `username` - The email or username of the user
    /// * `password`
    ///
    /// # Returns
    ///
    /// Returns a JWT token to fetch the cognito token
    async fn login(username: &str, password: &str) -> Result<String>;
    async fn forgot_password(username: &str) -> Result<String>;
    async fn confirm_forgot_password(
        username: &str,
        new_password: &str,
        confimation_code: &str,
    ) -> Result<String>;
    async fn change_password(
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<String>;
}

pub struct CognitoIdentityProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub userpool_id: String,
}

pub struct CognitoIdentityProvider {
    pub config: CognitoIdentityProviderConfig,
    pub client: Client,
}

impl CognitoIdentityProvider {
    pub async fn new(config: CognitoIdentityProviderConfig) -> Self {
        let env_config = aws_config::load_from_env().await;
        let client = Client::new(&env_config);
        Self { config, client }
    }
}
