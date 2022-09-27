use super::*;
use aws_config;
use aws_sdk_cognitoidentityprovider::types::SdkError;
use aws_sdk_cognitoidentityprovider::Client;
use aws_sdk_cognitoidentityprovider::{error::*, model::*};
use base64::encode;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

    /// Computes the HmacSha256 code which is needed for
    /// certain operations with the cognito api
    ///
    ///
    /// # Arguments
    ///
    /// `username` - the username of the user associated
    /// with the desired action
    ///
    /// # Returns
    ///
    /// The security code
    ///
    /// # Example
    ///
    /// ```
    /// # use rust_pastureen_portal_lib::CognitoIdentityProviderConfig;
    /// # use rust_pastureen_portal_lib::CognitoIdentityProvider;
    /// use base64::encode;
    /// use hex_literal::hex;
    ///
    /// let provider = tokio_test::block_on(CognitoIdentityProvider::new(
    ///     CognitoIdentityProviderConfig{
    ///         client_id: String::from("client_id"),
    ///         client_secret: String::from("client_secret"),
    ///         userpool_id: String::from("userpool_id")
    ///     }
    /// ));
    ///
    /// let code = provider.compute_hash(&"username");
    /// let ans = hex!("395e8b121c049b00dd1997b42d9698bf8f437475f044cd7789d87b35ba36a923");
    /// assert_eq!(&encode(ans),&code);
    ///
    ///
    /// ```
    ///
    pub fn compute_hash(&self, username: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.config.client_secret.as_bytes()).unwrap();
        mac.update(format!("{}{}", username, self.config.client_id).as_bytes());
        let result = mac.finalize();
        let code = result.into_bytes();
        println!("{:?}", code);
        encode(code)
    }
}

#[async_trait]
impl IdentityProvider for CognitoIdentityProvider {
    async fn signup(&self, email: &str, username: &str) -> Result<String> {
        let result = self
            .client
            .admin_create_user()
            .user_pool_id(&self.config.userpool_id)
            .username(username)
            .user_attributes(AttributeType::builder().name("email").value(email).build())
            .send()
            .await;

        if let Ok(res) = result {
            return Ok(res.user.unwrap().username.unwrap().to_owned());
        } else {
            let err = result.unwrap_err();

            if let SdkError::ServiceError {
                err: service_error, ..
            } = &err
            {
                match service_error.kind {
                    AdminCreateUserErrorKind::UsernameExistsException(_) => {
                        return Err(Whoops {
                            err_type: "cognito-username-exists".into(),
                            reason: format!("username {}, is already taken", username),
                            context: "While creating a new user.".into(),
                            suggestion: "Try using a different username to signup.".into(),
                        })
                    }
                    _ => {}
                }
            }

            return Err(Whoops {
                err_type: "cognito-sdk-unknown".into(),
                context: "While creating a new user.".into(),
                reason: format!("{}", err),
                suggestion: "Be a better programmer.".into(),
            });
        }
    }

    async fn login(&self, username: &str, password: &str) -> Result<String> {
        todo!()
    }

    async fn forgot_password(&self, username: &str) -> Result<String> {
        todo!()
    }

    async fn confirm_forgot_password(
        &self,
        username: &str,
        new_password: &str,
        confimation_code: &str,
    ) -> Result<String> {
        todo!()
    }

    async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<String> {
        todo!()
    }
}

#[test]
fn integration() {
    use std::env;
    async fn run() {
        let userpool_id = env::var("USERPOOL_ID").expect("Missing env var USERPOOL_ID");
        let client_id = env::var("CLIENT_ID").expect("Missing env var CLIENT_ID");
        let client_secret = env::var("CLIENT_SECRET").expect("Missing env var CLIENT_SECRET");

        let provider = CognitoIdentityProvider::new(CognitoIdentityProviderConfig {
            client_id,
            client_secret,
            userpool_id,
        })
        .await;

        // Signup

        let username = provider
            .signup("20544dk@gmail.com", "TEST_USER")
            .await
            .expect("Creating user should not fail");

        assert_eq!(username, "TEST_USER");

        // Signup with existing username

        let result = provider
            .signup("20544dk@gmail.com", "TEST_USER")
            .await
            .expect_err("Should fail because username exists");

        assert_eq!("cognito-username-exists", result.err_type);
    }

    tokio_test::block_on(run());
}
