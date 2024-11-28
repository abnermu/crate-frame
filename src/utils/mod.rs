use base64::Engine;
use hmac::Mac;
use log as logger;
use std::{ffi::CStr, os::raw::{c_char, c_long}, path::PathBuf, process::Command, str::FromStr, sync::{Arc, Mutex}, collections::HashMap};
use tauri::Manager;

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