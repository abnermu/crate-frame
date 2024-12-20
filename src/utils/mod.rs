use base64::Engine;
use hmac::Mac;
use log as logger;
use sm3::Digest;
use std::{collections::HashMap, ffi::CStr, io::{Cursor, Read}, os::raw::{c_char, c_long}, path::PathBuf, process::Command, str::FromStr, sync::{Arc, Mutex}};
use tauri::Manager;
use asn1_rs::{ToDer, FromDer};
use image::GenericImageView;

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
        let mut final_time = chrono::Local::now();
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
    /// 生成云库接口token(SM2方式)
    pub fn create_cloud_token_default(app_key: &str, enc_pub_key: &str, sign_pri_key: &str) -> String {
        TokenUtil::create_cloud_token(app_key, enc_pub_key, sign_pri_key, TokenUtil::TOKEN_VALID_MINUTES * 60)
    }
    /// 生成云库接口token(SM2方式)
    pub fn create_cloud_token(app_key: &str, enc_pub_key: &str, sign_pri_key: &str, timeout: i32) -> String {
        let mut final_time = chrono::Local::now();
        let seconds = chrono::Duration::seconds(timeout as i64);
        final_time = final_time + seconds;
        // key转为bytes
        match (hex::decode(enc_pub_key), hex::decode(sign_pri_key)) {
            (Ok(pub_key_bytes), Ok(pri_key_bytes)) => {
                // key由bytes形式转为实际的key实例
                match (gm_sm2::key::Sm2PublicKey::new(&pub_key_bytes), gm_sm2::key::Sm2PrivateKey::new(&pri_key_bytes)) {
                    (Ok(pub_key), Ok(pri_key)) => {
                        // 加密时间戮
                        match pub_key.encrypt(final_time.timestamp_millis().to_string().as_bytes(), false, gm_sm2::key::Sm2Model::C1C3C2) {
                            Ok(enc_data) => {
                                // 针对appKey + 时间戮 签名
                                let data_to_sign = format!("{}{}", app_key, final_time.timestamp_millis().to_string());
                                match pri_key.sign(None, data_to_sign.as_bytes()) {
                                    Ok(sig) => {
                                        // 签名值转为asn1形式
                                        let mut vec_signature: Vec<u8> = Vec::new();
                                        let r_bytes = &sig[0..32];
                                        let s_bytes = &sig[32..64];
                                        let mut r_pre: Vec<u8> = Vec::new();
                                        let mut s_pre: Vec<u8> = Vec::new();
                                        if let Some(r_first) = r_bytes.to_vec().first() {
                                            if *r_first > 127 {
                                                r_pre.push(0);
                                            }
                                        }
                                        if let Some(s_first) = s_bytes.to_vec().first() {
                                            if *s_first > 127 {
                                                s_pre.push(0);
                                            }
                                        }
                                        let _ = asn1_rs::Integer::new(&[&r_pre[..], r_bytes].concat()[..]).write_der(&mut vec_signature);
                                        let _ = asn1_rs::Integer::new(&[&s_pre[..], s_bytes].concat()[..]).write_der(&mut vec_signature);
                                        let seq_signature = asn1_rs::Sequence::new(vec_signature.into());
                                        match seq_signature.to_der_vec() {
                                            Ok(der_bytes) => {
                                                return format!("{}@{}@{}", app_key, hex::encode(enc_data), hex::encode(der_bytes));
                                            },
                                            Err(err) => logger::error!("error occured when asn1 signature bytes: {}", err),
                                        }
                                    },
                                    Err(err) => logger::error!("error occured when sign data: {}", err),
                                }
                            },
                            Err(err) => logger::error!("error occured when encrypt data: {}", err),
                        }
                    },
                    _ => logger::error!("error occured when convert key bytes to key instance"),
                }
            },
            _ => logger::error!("error occured when decode key from hex to bytes"),
        }
        String::from("")
    }
    /// 进行3des加密，key用字符串
    pub fn encrypt_desede_default(data: &str, key: &str) -> String {
        TokenUtil::encrypt_desede(data, TokenUtil::get_desede_key(key))
    }
    /// 进行3des加密
    pub fn encrypt_desede(data: &str, key: Vec<u8>) -> String {
        let mut data_bytes: Vec<u8> = data.as_bytes().to_vec();
        TokenUtil::pkcs5padding_data(&mut data_bytes);
        let cipher_vec: Vec<u8> = easydes::easydes::triple_des_ecb(&key, &mut data_bytes, easydes::easydes::Des::Encrypt);
        base64::engine::general_purpose::STANDARD.encode(cipher_vec)
    }
    /// 手动进行数据填充
    fn pkcs5padding_data(input: &mut Vec<u8>) {
        if input.len() % 8 != 0 {
            let len: usize = input.len();
            let rest_length: usize = 8 - len % 8;
            let mut padding: Vec<u8> = vec![rest_length as u8; rest_length];
            input.append(&mut padding);
        }
        else {
            let mut padding: Vec<u8> = vec![0x08 as u8; 8];
            input.append(&mut padding);
        }
    }
    /// 获取3des加密用的key
    fn get_desede_key(key: &str) -> Vec<u8> {
        let key_md5 = md5::compute(key.as_bytes());
        let mut key_bytes: Vec<u8> = vec![0; 24];
        for i in 0..24 {
            key_bytes[i] = key_md5[i % 16];
        }
        key_bytes
    }
}

/// 字符串工具类
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

/// 日志工具类
pub struct LogUtil;
impl LogUtil {
    /// 初始化日志保存路径等信息
    /// # 参数
    /// - `app` 应用实例
    /// - `app_state_reuse` 应用状态管理结构
    pub fn init_logger(app: &mut tauri::App, app_state_reuse: Arc<Mutex<crate::AppState>>) {
        let mut log_targets: Vec<tauri_plugin_log::Target> = Vec::new();
        let mut log_path_inited: bool = false;
        let mut custom_log_path: PathBuf = PathBuf::default();
        let custom_log_name = format!("{}-{}", String::from(&app.package_info().name), chrono::Local::now().format("%Y%m%d").to_string());
        if let Ok(exe_dir) = app.path().resource_dir() {
            crate::AppState::set_exe_dir(&exe_dir.to_string_lossy(), &app_state_reuse);
            let resource_dir: PathBuf = [&exe_dir.to_string_lossy(), "resources"].iter().collect();
            crate::AppState::set_resource_dir(&resource_dir.to_string_lossy(), &app_state_reuse);
            // 测试环境使用工程目录下的logs作为日志文件夹
            if cfg!(debug_assertions) {
                if let Some(tgt_dir) = exe_dir.parent() {
                    if let Some(src_dir) = tgt_dir.parent() {
                        if let Some(pro_dir) = src_dir.parent() {
                            custom_log_path = [&pro_dir.to_string_lossy(), "logs"].iter().collect();
                            log_path_inited = true;
                        }
                    }
                }
            }
        }
        if let Ok(data_dir) = app.path().app_data_dir() { 
            crate::AppState::set_data_dir(&data_dir.to_string_lossy(), &app_state_reuse);
            let pdf_ds_dir: PathBuf = [&data_dir.to_string_lossy(), "pdfTemp", "ds"].iter().collect();
            let pdf_vr_dir: PathBuf = [&data_dir.to_string_lossy(), "pdfTemp", "vr"].iter().collect();
            let java_args_dir: PathBuf = [&data_dir.to_string_lossy(), "javaArgs"].iter().collect();
            crate::AppState::set_pdf_digest_sign_dir(&pdf_ds_dir.to_string_lossy(), &app_state_reuse);
            crate::AppState::set_pdf_verify_dir(&pdf_vr_dir.to_string_lossy(), &app_state_reuse);
            crate::AppState::set_java_args_dir(&java_args_dir.to_string_lossy(), &app_state_reuse);
            // 生产环境下使用%app_data%/appName/logs作为日志文件夹
            if !cfg!(debug_assertions) {
                custom_log_path = [&data_dir.to_string_lossy(), "logs"].iter().collect();
                log_path_inited = true;
            }
        }
        if log_path_inited {
            crate::AppState::set_log_dir(&custom_log_path.to_string_lossy(), &app_state_reuse);
            crate::AppState::set_log_file_name(&custom_log_name, &app_state_reuse);
            // 如果需要修改日志文件地址的话就需要使用Folder，如果使用tauri默认的日志保存路径的话就使用LogDir
            log_targets.push(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Folder { path: custom_log_path, file_name: Some(custom_log_name) }));
            // tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir { file_name: Some(custom_log_name) }),
            log_targets.push(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout));
            log_targets.push(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Webview));
            let _ = app.handle().plugin(
                tauri_plugin_log::Builder::default()
                    .level(log::LevelFilter::Info)
                    .targets(log_targets)
                    .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepAll)
                    .max_file_size(10 * 1024 * 1024) // 10M
                    .build(),
            );
        }
    }
}

/// 文件工具类
pub struct FileUtil;
impl FileUtil {
    /// 从响应header中取文件名
    pub fn get_file_name_from_header(headers: &http::header::HeaderMap) -> String {
        if headers.contains_key(hyper::header::CONTENT_DISPOSITION) {
            if let Some(hd_disposition) = headers.get(hyper::header::CONTENT_DISPOSITION) {
                match hd_disposition.to_str() {
                    Ok(disposition) => {
                        if let Some(captures) = regex::Regex::new(r"(?i)filename=(.+)$").unwrap().captures(disposition) {
                            if captures.len() > 1 {
                                if let Some(match_item) = captures.get(1) {
                                    return match_item.as_str().to_string()
                                }
                            }
                            else {
                                logger::warn!("capture result false");
                            }
                        }
                        else {
                            logger::warn!("can not capture file name from response header");
                        }
                    },
                    Err(err) => {
                        logger::error!("convert header content_disposition to str failed: {}", err);
                    },
                };
            }
            else {
                logger::warn!("can not get content_disposition from header map");
            }
        }
        String::from("")
    }
    /// 通过字符串获取文件名
    /// # 参数
    /// - `file_dir` 文件路径
    /// - `with_ext` 是否包含扩展名
    pub fn get_file_name(file_dir: &str, with_ext: bool) -> String {
        match PathBuf::from_str(file_dir) {
            Ok(file_path) => FileUtil::get_file_name_from_path(file_path, with_ext),
            Err(err) => {
                logger::error!("error occured when convert path string to pathbuf: {}", err);
                String::from("")
            }
        }
    }
    /// 通过pathbuf获取文件名
    /// # 参数
    /// - `file_path` 文件路径
    /// - `with_ext` 是否包含扩展名
    pub fn get_file_name_from_path(file_path: PathBuf, with_ext: bool) -> String {
        if let Some(file_name) = file_path.file_name() {
            if with_ext {
                return file_name.to_string_lossy().to_string();
            }
            else {
                let ext = FileUtil::get_extension_from_path(file_path.clone());
                let ext_reg = format!("\\.{}$", ext);
                return regex::Regex::new(&ext_reg).unwrap().replace(file_name.to_string_lossy().to_string().as_str(), "").to_string();
            }
        }
        String::from("")
    }
    /// 通过字符串获取文件扩展名
    /// # 参数
    /// - `file_dir` 文件路径
    pub fn get_extension(file_dir: &str) -> String {
        match PathBuf::from_str(file_dir) {
            Ok(file_path) => FileUtil::get_extension_from_path(file_path),
            Err(err) => {
                logger::error!("error occured when convert path string to pathbuf: {}", err);
                String::from("")
            }
        }
    }
    /// 通过pathbuf读取文件扩展名
    /// # 参数
    /// - `file_path` 文件路径
    pub fn get_extension_from_path(file_path: PathBuf) -> String {
        if let Some(extension) = file_path.extension() {
            return extension.to_string_lossy().to_string();
        }
        String::from("")
    }
}

/// java操作命令结构
pub struct JavaCommander {
    pub command: PathBuf,
    pub args: Vec<String>,
}
impl JavaCommander {
    /// Vec<String>类型的参数转为Vec<&str>
    pub fn get_args(&self) -> Vec<&str> {
        self.args.iter().map(|arg| arg.as_str()).collect()
    }
}
/// Java操作工具类
pub struct JavaUtil;
impl JavaUtil {
    pub fn spawn_java(commander: JavaCommander) -> String {
        logger::info!("执行java命令：{}\n命令参数：{:?}", &commander.command.to_str().unwrap_or(""), commander.get_args());
        let mut cmd = Command::new(&commander.command);
        match cmd.args(&commander.get_args()).output() {
            Ok(output) => {
                let out_str = String::from_utf8_lossy(&output.stdout[..]).to_string();
                let err_str = String::from_utf8_lossy(&output.stderr[..]).to_string();
                logger::info!("java执行结果-返回值：{}\njava执行结果-错误信息：{}", &out_str, &err_str);
                let reg = regex::Regex::new(r"\{.*\}").unwrap();
                let captures = reg.captures_iter(&out_str);
                if let Some(capture_last) = captures.last() {
                    if let Some(match_item) = capture_last.get(capture_last.len() - 1) {
                        return match_item.as_str().to_string();
                    }
                }
            },
            Err(err) => {
                logger::error!("error occured when run java function with params【{}】: {}", &commander.get_args().join("|||"), err);
            }
        }
        String::from("")
    }
    pub fn make_spawn_command(state: &Arc<Mutex<crate::AppState>>, func_name: &str, func_arg: serde_json::Value) -> JavaCommander {
        let mut args_obj: serde_json::Value = func_arg.clone();
        args_obj["cmd"] = serde_json::json!(func_name.to_string());
        // 尝试把参数写入到文件，如果写入失败的话使用原参数
        let args_file_name = format!("{}-{}.arg", func_name, chrono::Local::now().format("%Y%m%d%H%M%S%3f").to_string());
        let args_path: PathBuf = [&crate::AppState::get_java_args_dir(&state), args_file_name.as_str()].iter().collect();
        match std::fs::write(args_path.clone(), func_arg.to_string().as_bytes()) {
            Ok(_) => {
                args_obj = serde_json::json!({
                    "cmd": func_name.to_string(),
                    "argPath": args_path.to_string_lossy().to_string(),
                });
            },
            Err(err) => {
                logger::error!("error occured when write java arguments to file, will use original args: {}", err);
            }
        }
        let java_path: PathBuf = [&crate::AppState::get_resource_dir(&state), "extraResources", "java", "jre", "bin", "javaw.exe"].iter().collect();
        let jar_path: PathBuf = [&crate::AppState::get_resource_dir(&state), "extraResources", "java", "file-tender-jar-1.0.0.jar"].iter().collect();
        JavaCommander { 
            command: java_path.clone(), 
            args: vec![
                "-Dfile.encoding=UTF-8".to_string(),
                "-jar".to_string(),
                jar_path.to_string_lossy().to_string(),
                base64::engine::general_purpose::STANDARD.encode(args_obj.to_string().as_bytes()),
            ] 
        }
    }
}

/// 中招基础工具类
pub struct ZhongZhaoUtil;
impl ZhongZhaoUtil {
    pub const DEFAULT_ACCESS_SECRET: &str = "B32D22CABBB24963A42F10FFF49CF779";
    pub const DEFAULT_CLIENT_ID: &str = "Z0010020035";
    pub const DEFAULT_CLIENT_SECRET: &str = "D5BEA3E0F5A64BD19CB374C1876F1026";
    pub const DEFAULT_SERVICE_URL: &str = "http://218.60.154.155:8877/cashare/";
    pub const DEFAULT_TRADING_SYSTEM_CODE: &str = "X2100000027";
    pub const DEFAULT_SIGNATURE_SECRET: &str = "B32D22CABBB24963A42F10FFF49CF779";
    pub const DEFAULT_JWT_KEY: &str = "8784od7belusyfuw7oiq4i0mbzacxp32";
    pub const DEFAULT_JWT_TRADING_SYSTEM_KEY: &str = "8784od7belusyfuw7oiq4i0mbzacxp32";

    /// 内部方法，中招通用请求
    pub async fn zz_common_request(body: &str, feature_code: &str) -> serde_json::Value {
        let headers = ZhongZhaoUtil::zz_make_headers(ZhongZhaoUtil::DEFAULT_CLIENT_ID, ZhongZhaoUtil::DEFAULT_CLIENT_SECRET, ZhongZhaoUtil::DEFAULT_TRADING_SYSTEM_CODE, 
            feature_code, "electronicSealSignature", "V1.0.0", body, ZhongZhaoUtil::DEFAULT_SIGNATURE_SECRET);
        let client = reqwest::Client::new();
        let mut form = HashMap::new();
        form.insert("businessData", body);
        logger::debug!("request to zz server, the headers is {:?} and the body is {:?}", &headers, &form);
        match client.post(format!("{}/CAShare/Components", ZhongZhaoUtil::DEFAULT_SERVICE_URL)).headers(headers).form(&form).send().await {
            Ok(res) => {
                match res.json::<serde_json::Value>().await {
                    Ok(rtn) => {
                        return rtn.clone();
                    },
                    Err(err) => {
                        logger::error!("try to convert zz response to json object failed: {}", err);
                    }
                }
            },
            Err(err) => {
                logger::error!("try to request zz server {} failed: {}", format!("{}/CAShare/Components", ZhongZhaoUtil::DEFAULT_SERVICE_URL), err);
            }
        }
        serde_json::json!({})
    }

    /// 内部方法，中招生成通用请求header
    pub fn zz_make_headers(client_id: &'static str, client_secret: &'static str, trading_system_code: &'static str, 
        feature_code: &str, service_code: &'static str, version: &'static str, 
        body: &str, signature_secret: &'static str) -> reqwest::header::HeaderMap 
    {
        let curr_time = chrono::Local::now();
        let time_stamp = curr_time.timestamp_millis().to_string();
        let request_uuid = uuid::Uuid::new_v4();
        let authorization = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", client_id, client_secret).as_bytes()));
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append("x-sdk-invoke-type", reqwest::header::HeaderValue::from_static("common"));
        headers.append("ServiceCode", reqwest::header::HeaderValue::from_static(service_code));
        if let Ok(hv_feature_code) = reqwest::header::HeaderValue::from_str(feature_code) {
            headers.append("FeatureCode", hv_feature_code);
        }
        headers.append("Version", reqwest::header::HeaderValue::from_static(version));
        headers.append("TradingSystemCode", reqwest::header::HeaderValue::from_static(trading_system_code));
        if let Ok(hv_timestamp) = reqwest::header::HeaderValue::from_str(&time_stamp) {
            headers.append("Timestamp", hv_timestamp);
        }
        if let Ok(hv_request_uuid) = reqwest::header::HeaderValue::from_str(&request_uuid.to_string()) {
            headers.append("Nonce", hv_request_uuid);
        }
        if let Ok(hv_authorization) = reqwest::header::HeaderValue::from_str(&authorization) {
            headers.append("Authorization", hv_authorization);
        }
        if let Ok(hv_signature) = reqwest::header::HeaderValue::from_str(
            &ZhongZhaoUtil::zz_cal_signature(body, &time_stamp, &request_uuid.to_string(), &authorization, feature_code, service_code, version, signature_secret)
        ) {
            headers.append("Signature", hv_signature);
        }
        headers
    }

    /// 内部方法，计算中招的请求签名
    pub fn zz_cal_signature(body: &str, time_stamp: &str, request_uuid: &str, authorization: &str, 
        feature_code: &str, service_code: &str, version: &str, signature_secret: &str) -> String 
    {
        let mut vec_message: Vec<String> = vec![];
        vec_message.push(format!("{}={}", "Authorization", authorization));
        vec_message.push(format!("{}={}", "FeatureCode", feature_code));
        vec_message.push(format!("{}={}", "Nonce", request_uuid));
        vec_message.push(format!("{}={}", "ServiceCode", service_code));
        vec_message.push(format!("{}={}", "Timestamp", time_stamp));
        vec_message.push(format!("{}={}", "Version", version));
        vec_message.push(format!("{}={}", "businessData", body));
        let message = format!("{}{}{}", vec_message.join(","), &time_stamp[0..3], &request_uuid[0..3]);
        match hmac::Hmac::<sm3::Sm3>::new_from_slice(signature_secret.as_bytes()) {
            Ok(mut hmac) => {
                hmac.update(message.as_bytes());
                let rtn = hex::encode(hmac.finalize().into_bytes());
                return rtn;
            },
            Err(err) => {
                logger::error!("hmac-sm3 hash failed: {}", err);
            }
        }
        String::from("")
    }

    /// 内部方法，生成cebs属性对象
    pub fn zz_build_cebs() -> serde_json::Value {
        serde_json::json!({
            "accessKeySecret": ZhongZhaoUtil::DEFAULT_ACCESS_SECRET,
            "clientId": ZhongZhaoUtil::DEFAULT_CLIENT_ID,
            "clientSecret": ZhongZhaoUtil::DEFAULT_CLIENT_SECRET,
            "tradingSystemCode": ZhongZhaoUtil::DEFAULT_TRADING_SYSTEM_CODE,
            "serviceUrl": ZhongZhaoUtil::DEFAULT_SERVICE_URL,
            "signatureSecret": ZhongZhaoUtil::DEFAULT_SIGNATURE_SECRET,
        })
    }
}

/// 图片处理工具类
pub struct ImageUtil;
impl ImageUtil {
    /// 图片缩放
    pub fn resize_image(img: &str, max_width: f64) -> String {
        match base64::engine::general_purpose::STANDARD.decode(img) {
            Ok(img_bytes) => {
                match image::ImageReader::new(Cursor::new(&img_bytes[..])).with_guessed_format() {
                    Ok(img_reader) => {
                        match img_reader.decode() {
                            Ok(mut img_ins) => {
                                let (ori_width, ori_height) = img_ins.dimensions();
                                if ori_width as f64 > max_width {
                                    let scale: f64 = max_width / ori_width as f64;
                                    let scaled_width = ori_width as f64 * scale;
                                    let scaled_height = ori_height as f64 * scale;
                                    img_ins = img_ins.resize(scaled_width as u32, scaled_height as u32, image::imageops::FilterType::Lanczos3);
                                    let mut scaled_img_bytes: Vec<u8> = Vec::new();
                                    match img_ins.write_to(&mut Cursor::new(&mut scaled_img_bytes), image::ImageFormat::Png) {
                                        Ok(_) => return base64::engine::general_purpose::STANDARD.encode(&scaled_img_bytes[..]),
                                        Err(err) => {
                                            logger::error!("write resized image to bytes failed: {}", err);
                                        }
                                    }
                                }
                                else {
                                    logger::info!("the seal image no need to be resized");
                                }
                            },
                            Err(err) => {
                                logger::error!("get dynamic image instance failed: {}", err);
                            }
                        }
                    },
                    Err(err) => {
                        logger::error!("create image reader failed: {}", err);
                    }
                }
            },
            Err(err) => {
                logger::error!("try to convert sealImage from base64 to bytes failed: {}", err);
            }
        }
        img.to_string()
    }
}

pub struct NetInterface {
    pub name: String,
    pub ipv4: String,
    pub mac: String,
}

/// 系统相关工具类
pub struct SysUtil;
impl SysUtil {
    /// 获取硬盘序列号
    pub fn get_disk_sid() -> Option<String> {
        if std::env::consts::OS == "macos" {
            return SysUtil::get_disk_sid_mac();
        }
        else if std::env::consts::OS == "linux" {
            return SysUtil::get_disk_sid_linux();
        }
        else {
            return SysUtil::get_disk_sid_win();
        }
    }
    /// windows环境获取硬盘序列号
    pub fn get_disk_sid_win() -> Option<String> {
        let mut cmd = Command::new("powershell");
        match cmd.args(["-Command", "Get-WmiObject -Class Win32_DiskDrive | Select-Object -ExpandProperty SerialNumber"]).output() {
            Ok(output) => {
                if output.status.success() {
                    return Some(String::from_utf8_lossy(&output.stdout).to_string());
                }
                else {
                    logger::error!("[获取硬盘序列号]失败");
                }
            }
            Err(err) => logger::error!("[获取硬盘序列号]执行命令行异常: {:?}", err),
        }
        None
    }
    /// mac环境获取硬盘序列号
    pub fn get_disk_sid_mac() -> Option<String> {
        None
    }
    /// linux环境获取硬盘序列号
    pub fn get_disk_sid_linux() -> Option<String> {
        None
    }
    /// 获取CPU序列号
    pub fn get_cpu_sid() -> Option<String> {
        if std::env::consts::OS == "macos" {
            return SysUtil::get_cpu_sid_mac();
        }
        else if std::env::consts::OS == "linux" {
            return SysUtil::get_cpu_sid_linux();
        }
        else {
            return SysUtil::get_cpu_sid_win();
        }
    }
    /// windows环境获取CPU序列号
    pub fn get_cpu_sid_win() -> Option<String> {
        let mut cmd = Command::new("powershell");
        match cmd.args(["-Command", "Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty ProcessorId"]).output() {
            Ok(output) => {
                if output.status.success() {
                    return Some(String::from_utf8_lossy(&output.stdout).to_string());
                }
                else {
                    logger::error!("[获取CPU序列号]失败");
                }
            }
            Err(err) => logger::error!("[获取CPU序列号]执行命令行异常: {:?}", err),
        }
        None
    }
    /// mac环境获取CPU序列号
    pub fn get_cpu_sid_mac() -> Option<String> {
        None
    }
    /// linux环境获取CPU序列号
    pub fn get_cpu_sid_linux() -> Option<String> {
        None
    }
    /// 获取网卡信息
    pub fn get_net_interface() -> Option<NetInterface> {
        if std::env::consts::OS == "macos" {
            return SysUtil::get_net_interface_mac();
        }
        else if std::env::consts::OS == "linux" {
            return SysUtil::get_net_interface_linux();
        }
        else {
            return SysUtil::get_net_interface_win();
        }
    }
    /// windows环境获取网卡信息
    pub fn get_net_interface_win() -> Option<NetInterface> {
        let mut cmd = Command::new("powershell");
        match cmd.args(["-Command", "Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true } | Select-Object Name, MACAddress, @{Name=\"IPAddress\";Expression={(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter \"Description = '$($_.Name)'\").IPAddress}}"]).output() {
            Ok(output) => {
                if output.status.success() {
                    let network_info = String::from_utf8_lossy(&output.stdout).to_string();
                    let reg_mac = regex::Regex::new(r"[\r\s]*([\w\d]{2}(:[\w\d]{2}){5})").unwrap();
                    let reg_ip = regex::Regex::new(r"[\r\s]*(\d{1,3}(.\d{1,3}){3})").unwrap();
                    let reg_ip_wrapper = regex::Regex::new(r"[\r\s]*\{.*\}").unwrap();
                    let reg_virtual = regex::Regex::new(r"(?i)vethernet|virtual").unwrap();
                    for item in network_info.split("\n").collect::<Vec<&str>>() {
                        if reg_mac.is_match(item) && reg_ip.is_match(item) && reg_ip_wrapper.is_match(item) && !reg_virtual.is_match(item) {
                            let mac = reg_mac.captures(item).unwrap().get(0).unwrap().as_str();
                            let ip = reg_ip.captures(item).unwrap().get(0).unwrap().as_str();
                            let item_noip = reg_ip_wrapper.replace(&item, "");
                            let name = reg_mac.replace(&item_noip, "");
                            return Some(NetInterface {
                                name: name.to_string(),
                                ipv4: ip.to_string(),
                                mac: mac.to_string(),
                            });
                        }
                    }
                }
                else {
                    logger::error!("[获取网卡信息]失败");
                }
            }
            Err(err) => logger::error!("[获取网卡信息]执行命令行异常: {:?}", err),
        }
        None
    }
    /// mac环境获取网卡信息
    pub fn get_net_interface_mac() -> Option<NetInterface> {
        None
    }
    /// linux获取网卡信息
    pub fn get_net_interface_linux() -> Option<NetInterface> {
        None
    }
    /// 获取机器码
    pub fn get_machine_code() -> Option<String> {
        let diskid = SysUtil::get_disk_sid();
        let cpuid = SysUtil::get_cpu_sid();
        let net_interface = SysUtil::get_net_interface();
        if diskid.is_some() && cpuid.is_some() && net_interface.is_some() {
            let mut wrapper: Vec<u8> = Vec::new();
            let _ = asn1_rs::Utf8String::new(diskid.unwrap().as_str()).write_der(&mut wrapper);
            let _ = asn1_rs::Utf8String::new(cpuid.unwrap().as_str()).write_der(&mut wrapper);
            let _ = asn1_rs::Utf8String::new(&net_interface.unwrap().mac).write_der(&mut wrapper);
            let seq_wrapper = asn1_rs::Sequence::new(wrapper.into());
            match seq_wrapper.to_der_vec() {
                Ok(seq_bytes) => {
                    let mut hasher = sm3::Sm3::new();
                    hasher.update(seq_bytes);
                    let code_bytes = hasher.finalize();
                    return Some(StringUtil::bytes_to_hex(&code_bytes[..]));
                },
                Err(err) => logger::error!("生成机器码异常：{:?}", err),
            }
        }
        None
    }
    /// 验证机器码有效性
    pub fn license_check(machine_str: &str, lic_path: &str) -> bool {
        match hex::decode(machine_str) {
            Ok(machine_bytes) => {
                match std::fs::File::open(lic_path) {
                    Ok(mut file) => {
                        let mut buffer: Vec<u8> = Vec::new();
                        match file.read_to_end(&mut buffer) {
                            Ok(_) => {
                                match asn1_rs::Sequence::from_der_and_then(&buffer, |bytes| {
                                    match asn1_rs::OctetString::from_der(bytes) {
                                        Ok((bytes, oct_machinecode)) => {
                                            match asn1_rs::OctetString::from_der(bytes) {
                                                Ok((bytes, oct_expire)) => {
                                                    match asn1_rs::OctetString::from_der(bytes) {
                                                        Ok((bytes, oct_sig)) => {
                                                            let mut machine_code: Vec<u8> = Vec::new();
                                                            let mut expire: Vec<u8> = Vec::new();
                                                            let mut signature: Vec<u8> = Vec::new();
                                                            machine_code.extend_from_slice(oct_machinecode.as_cow());
                                                            expire.extend_from_slice(oct_expire.as_cow());
                                                            signature.extend_from_slice(oct_sig.as_cow());
                                                            Ok((bytes, (machine_code, expire, signature)))
                                                        },
                                                        Err(err) => Err(err),
                                                    }
                                                },
                                                Err(err) => Err(err),
                                            }
                                        },
                                        Err(err) => Err(err),
                                    }
                                }) {
                                    Ok((_bytes, (machine_code, expire, signature))) => {
                                        if machine_str != hex::encode(&machine_code) {
                                            logger::error!("机器码与算码不匹配");
                                        }
                                        else {
                                            let expire_final = String::from_utf8_lossy(&expire).to_string();
                                            let expire_trim = &expire_final[3..(expire_final.len() - 3)];
                                            let expire_reverse = expire_trim.chars().rev().collect::<String>();
                                            match expire_reverse.parse::<i64>() {
                                                Ok(expire_time) => {
                                                    if expire_time < chrono::Local::now().timestamp() {
                                                        logger::error!("算码已过期");
                                                    }
                                                    else {
                                                        let pub_key = "0406fa6fa7bf9c00e88902538633878560a000eb7188e53bc017d2794d9de303e0d99aeeccc40ba83b51254391c789bef1748103f0fc626edc2beb8899238e40d0";
                                                        match hex::decode(pub_key) {
                                                            Ok(key_bytes) => {
                                                                match gm_sm2::key::Sm2PublicKey::new(&key_bytes) {
                                                                    Ok(key) => {
                                                                        match key.verify(None, &machine_bytes, &signature) {
                                                                            Ok(()) => return true,
                                                                            Err(err) => println!("算码验证失败：{:?}", err),
                                                                        }
                                                                    },
                                                                    Err(err) => logger::error!("key转换失败：{:?}", err),
                                                                }
                                                            },
                                                            Err(err) => logger::error!("key转换失败：{:?}", err),
                                                        }
                                                    }
                                                }
                                                ,
                                                Err(err) => logger::error!("time convert failed: {:?}", err),
                                            }
                                        }
                                    },
                                    Err(err) => logger::error!("算码解析失败：{:?}", err),
                                }
                            },
                            Err(err) => logger::error!("算码读取失败：{:?}", err),
                        }
                    },
                    Err(err) => logger::error!("算码读取失败：{:?}", err),
                }
            },
            Err(err) => logger::error!("机器码解析失败：{:?}", err),
        }
        false
    }
}