use async_trait::async_trait;

#[async_trait]
pub trait IdentityProvider {
    async fn signup();
    async fn login();
    async fn forgot_password();
    async fn confirm_forgot_password();
    async fn change_password();
}

pub struct CognitoIdentityProvider {}
