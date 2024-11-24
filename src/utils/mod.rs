use base64::Engine;
use hmac::Mac;
use log as logger;
use std::{ffi::CStr, os::raw::{c_long, c_char}};

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
        match hmac::Hmac::<sha1::Sha1>::new_from_slice(app_secret.as_bytes()) {
            Ok(mut mac) => {
                mac.update(p2.as_bytes());
                let p3 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
                let p4 = regex::Regex::new(r"\/").unwrap().replace_all(
                    &regex::Regex::new(r"\+").unwrap().replace_all(&p3, "-").to_string(), "_"
                ).to_string();
                return format!("{}@{}@{}", app_key, p4, p2);
            },
            Err(err) => {
                logger::error!("key-secret Token生成失败：{}", err);
                return String:: from("");
            },
        }
    }
}

pub struct StringUtil;
impl StringUtil {
    /// 根据长度读取多个字符串的分组
    /// # 参数
    /// - `ptr` 字符串指针
    /// - `total_len` 指针指向的内存长度
    pub unsafe fn read_c_strings(ptr: *mut c_char, total_len: c_long) -> Vec<String> {
        let mut strings: Vec<String> = Vec::new();
        let mut current_start = 0;
        for i in 0..total_len {
            // 如果遇到\0 提取字符串
            if *ptr.offset(i as isize) == 0 {
                if current_start < i {
                    let slice = std::slice::from_raw_parts(ptr.offset(current_start as isize), (i - current_start) as usize);
                    match CStr::from_ptr(slice.as_ptr()).to_str() {
                        Ok(sub_str) => {
                            strings.push(sub_str.to_string());
                        },
                        Err(err) => {
                            logger::error!("字符串片断截取异常：{}", err);
                        }
                    }
                }
                current_start = i + 1;
            }
        }
        strings
    }

    /// 读单个字符串（以\0结束）
    /// # 参数
    /// - `ptr` 字符串指针
    pub unsafe fn read_c_string(ptr: *mut c_char) -> String {
        match CStr::from_ptr(ptr).to_str() {
            Ok(str) => str.to_string(),
            Err(..) => String::from(""),
        }
    }

    /// 根据长度读取字节数组
    /// # 参数
    /// - `ptr` 内存指针
    /// - `total_len` 指针指向的内存长度
    pub unsafe fn read_bytes(ptr: *mut u8, total_len: c_long) -> Vec<u8> {
        Vec::from_raw_parts(ptr, total_len as usize, total_len as usize)
    }

    /// 读取byte数组为hex
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.to_vec().iter().map(|byte| format!("{:02x}", byte)).collect::<String>()
    }
}