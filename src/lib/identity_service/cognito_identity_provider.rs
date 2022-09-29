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
    async fn signup(
        &self,
        email: &str,
        username: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>> {
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
                            err_type: IdentityProviderErrKind::UsernameExists,
                            reason: format!("username {}, is already taken", username),
                            context: "While creating a new user.".into(),
                            suggestion: "Try using a different username to signup.".into(),
                        })
                    }
                    _ => {}
                }
            }

            return Err(Whoops {
                err_type: IdentityProviderErrKind::Unknown,
                context: "While creating a new user.".into(),
                reason: format!("{}", err),
                suggestion: "Be a better programmer.".into(),
            });
        }
    }

    async fn login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<LoginResponse, Whoops<IdentityProviderErrKind>> {
        let result = self
            .client
            .admin_initiate_auth()
            .auth_flow(AuthFlowType::UserPasswordAuth)
            .auth_parameters("USERNAME", username)
            .auth_parameters("PASSWORD", password)
            .auth_parameters("SECRET_HASH", self.compute_hash(username))
            .send()
            .await;

        if let Ok(value) = result {
            if let Some(ChallengeNameType::NewPasswordRequired) = value.challenge_name() {
                return Err(Whoops {
                    err_type: IdentityProviderErrKind::NewPasswordNeeded,
                    context: "While trying to login.".into(),
                    reason: "A new password is needed".into(),
                    suggestion: "Try to change your password before attempting to login again."
                        .into(),
                });
            }

            if let None = value.authentication_result() {
                return Err(Whoops {
                    err_type: IdentityProviderErrKind::UnknownAuthChallenge,
                    context: "While trying to login.".into(),
                    reason: format!("{:?}",value.challenge_name().expect("challenge should exist when no authentication result is given")),
                    suggestion: "We encounted an unknwon authentication challenge, ensure that cognito user pool is setup according to this program's requirements."
                        .into(),
                });
            }

            let update_request = self
                .client
                .admin_update_user_attributes()
                .username(username)
                .user_pool_id(&self.config.userpool_id)
                .user_attributes(
                    AttributeType::builder()
                        .name("email_verified")
                        .value("true")
                        .build(),
                )
                .send()
                .await;

            if let Err(err) = update_request {
                return Err(Whoops {
                    err_type: IdentityProviderErrKind::Unknown,
                    context: "While trying to update user attribute at login.".into(),
                    reason: format!("{}", err),
                    suggestion: "Be a better developer.".into(),
                });
            }

            let authentication_result = value
                .authentication_result()
                .expect("None case should've been handled");

            return Ok(LoginResponse {
                access_token: authentication_result
                    .access_token()
                    .expect("Access token should be present")
                    .to_owned(),
                refresh_token: authentication_result
                    .refresh_token()
                    .expect("Refresh token should be present")
                    .to_owned(),
            });
        }

        let err = result.expect_err("Ok should've been handled");

        if let SdkError::ServiceError { err, .. } = &err {
            match err.kind {
                AdminInitiateAuthErrorKind::NotAuthorizedException(_)
                | AdminInitiateAuthErrorKind::UserNotFoundException(_) => {
                    return Err(Whoops {
                        err_type: IdentityProviderErrKind::IncorrectCredentials,
                        context: "While trying to login.".into(),
                        reason: "Supplied password and username were incorrect".into(),
                        suggestion: "Try using a valid username and password.".into(),
                    });
                }
                _ => {}
            }
        }
        return Err(Whoops {
            err_type: IdentityProviderErrKind::Unknown,
            context: "While trying to login.".into(),
            reason: format!("{}", err),
            suggestion: "Be a better developer.".into(),
        });
    }

    async fn forgot_password(
        &self,
        username: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>> {
        let result = self
            .client
            .forgot_password()
            .username(username)
            .secret_hash(self.compute_hash(username))
            .client_id(&self.config.client_id)
            .send()
            .await;

        if let Err(err) = result {
            if let SdkError::ServiceError { err, .. } = &err {
                match err.kind {
                    ForgotPasswordErrorKind::UserNotFoundException(_) => {
                        return Err(Whoops {
                            err_type: IdentityProviderErrKind::IncorrectCredentials,
                            context: "While trying to forget password.".into(),
                            reason: "Username could not be found".into(),
                            suggestion: "Try using a valid username.".into(),
                        });
                    }
                    _ => {}
                }
            }
            return Err(Whoops {
                err_type: IdentityProviderErrKind::Unknown,
                context: "While trying to forget password.".into(),
                reason: format!("{}", err),
                suggestion: "Be a better developer.".into(),
            });
        }

        return Ok(username.into());
    }

    async fn confirm_forgot_password(
        &self,
        username: &str,
        new_password: &str,
        confirmation_code: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>> {
        let result = self
            .client
            .confirm_forgot_password()
            .client_id(&self.config.client_id)
            .password(new_password)
            .confirmation_code(confirmation_code)
            .username(username)
            .secret_hash(self.compute_hash(username))
            .send()
            .await;

        if let Err(err) = result {
            if let SdkError::ServiceError { err, .. } = &err {
                match err.kind {
                    ConfirmForgotPasswordErrorKind::UserNotFoundException(_) => {
                        return Err(Whoops {
                            err_type: IdentityProviderErrKind::IncorrectCredentials,
                            context: "While trying to confirm forgot password.".into(),
                            reason: "Supplied username is invalid.".into(),
                            suggestion: "Try using a valid username.".into(),
                        })
                    },
                    ConfirmForgotPasswordErrorKind::CodeMismatchException(_)=>{
                        return Err(Whoops {
                            err_type: IdentityProviderErrKind::IncorrectCredentials,
                            context: "While trying to confirm forgot password.".into(),
                            reason: "Code is invalid".into(),
                            suggestion: "Try using a valid confirmation code or try \"forgot_password\" again.".into(),
                        })
                    },
                    _ => {
                        return Err(Whoops {
                            err_type: IdentityProviderErrKind::Unknown,
                            context: "While trying to confirm forgot password.".into(),
                            reason: format!("{}",err),
                            suggestion: "Be a better developer".into(),
                        })
                        
                    }
                }
            }
        }
        Ok(username.into())
    }

    async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<String, Whoops<IdentityProviderErrKind>> {
        todo!()
    }
}

#[test]
fn integration() {
    use std::env;
    async fn signup() {
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

        assert_eq!(IdentityProviderErrKind::UsernameExists, result.err_type);
    }

    async fn login_expect_change_password() {}

    // tokio_test::block_on(signup());
}
