use base64::Engine;
use hmac::Mac;
use log as logger;
use std::{ffi::CStr, os::raw::{c_char, c_long}, path::PathBuf, process::Command, str::FromStr, sync::{Arc, Mutex}};
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
            crate::AppState::set_pdf_digest_sign_dir(&pdf_ds_dir.to_string_lossy(), &app_state_reuse);
            crate::AppState::set_pdf_verify_dir(&pdf_vr_dir.to_string_lossy(), &app_state_reuse);
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
    pub fn make_spawn_command(state: &Arc<Mutex<crate::AppState>>, func_name: &str, mut func_arg: serde_json::Value) -> JavaCommander {
        let java_path: PathBuf = [&crate::AppState::get_resource_dir(&state), "extraResources", "java", "jre", "bin", "javaw.exe"].iter().collect();
        let jar_path: PathBuf = [&crate::AppState::get_resource_dir(&state), "extraResources", "java", "file-tender-jar-1.0.0.jar"].iter().collect();
        func_arg["cmd"] = serde_json::json!(func_name.to_string());
        JavaCommander { 
            command: java_path.clone(), 
            args: vec![
                "-Dfile.encoding=UTF-8".to_string(),
                "-jar".to_string(),
                jar_path.to_string_lossy().to_string(),
                base64::engine::general_purpose::STANDARD.encode(func_arg.to_string().as_bytes()),
            ] 
        }
    }
}
