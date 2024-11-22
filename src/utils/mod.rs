use base64::Engine;
use hmac::Mac;

/// token工具类
pub struct TokenUtil;
impl TokenUtil {
    /// 前端token的有效时间
    pub const TOKEN_VALID_MINUTES: i32 = 10;
    /// 生成token
    pub fn create_key_secret_token_default(app_key: &str, app_secret: &str) -> String {
        TokenUtil::create_key_secret_token(app_key, app_secret, TokenUtil::TOKEN_VALID_MINUTES * 60)
    }
    /// 生成token
    pub fn create_key_secret_token(app_key: &str, app_secret: &str, timeout: i32) -> String {
        let mut final_time = chrono::Utc::now();
        let seconds = chrono::Duration::seconds(timeout as i64);
        final_time = final_time + seconds;
        let p1 = (final_time.timestamp_millis() / 1000).to_string();
        let p2 = base64::engine::general_purpose::STANDARD.encode(p1.as_bytes());
        if let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(app_secret.as_bytes()) {
            mac.update(p2.as_bytes());
            let p3 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
            let p4 = regex::Regex::new(r"\/").unwrap().replace_all(
                &regex::Regex::new(r"\+").unwrap().replace_all(&p3, "-").to_string(), "_"
            ).to_string();
            return format!("{}@{}@{}", app_key, p4, p2);
        }
        String:: from("")
    }
}