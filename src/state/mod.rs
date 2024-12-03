use std::{path::PathBuf, str::FromStr, sync::{Arc, Mutex}};
use log as logger;

/// 应用状态
#[derive(Default)]
pub struct AppState {
    /// 新点驱动端口号
    pub ep_ca_port: i32,
    /// 本地起的端口号
    pub local_port: u16,
    /// 执行文件目录
    pub exe_dir: String,
    /// 资源文件目录 exe_dir/resources
    pub resource_dir: String,
    /// 数据文件目录 %appdata%/appname
    pub data_dir: String,
    /// 日志文件目录 %appdata%/appname/logs
    /// - 开发环境比较特殊，这个是在工程目录/logs
    pub log_dir: String,
    /// 日志文件名称
    pub log_file_name: String,
    /// pdf签章和哈希临时目录
    pub pdf_digest_sign_dir: String,
    /// pdf验签临时目录
    pub pdf_verify_dir: String,
    /// java执行参数文件目录
    pub java_args_dir: String,
    /// 用户登录信息
    pub user_info: serde_json::Value,
}
impl AppState {
    /// 初始化数据
    pub fn init() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(AppState::default()))
    }
    /// 获取新点驱动已经测试好的端口号
    pub fn get_ep_ca_port(state: &Arc<Mutex<AppState>>) -> i32 {
        match state.lock() {
            Ok(app_state) => app_state.ep_ca_port,
            Err(err) =>  {
                logger::error!("try to lock app state failed: {}", err);
                0
            },
        }
    }
    /// 重新设置新点驱动测试端口号
    pub fn set_ep_ca_port(port: i32, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => {
                app_state.ep_ca_port = port;
            },
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取本地端口号
    pub fn get_local_port(state: &Arc<Mutex<AppState>>) -> u16 {
        match state.lock() {
            Ok(app_state) => app_state.local_port,
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                0
            }
        }
    }
    /// 设置本地端口号
    pub fn set_local_port(port: u16, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.local_port = port,
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取执行文件目录
    pub fn get_exe_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.exe_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置执行文件目录
    pub fn set_exe_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.exe_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取资源文件目录
    pub fn get_resource_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.resource_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置资源文件目录
    pub fn set_resource_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.resource_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取数据文件目录
    pub fn get_data_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.data_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置数据文件目录
    pub fn set_data_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.data_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取日志文件目录
    pub fn get_log_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.log_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置日志文件目录
    pub fn set_log_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.log_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取日志文件名称
    pub fn get_log_file_name(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.log_file_name),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置日志文件名称
    pub fn set_log_file_name(file_name: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.log_file_name = file_name.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 获取pdf签章哈希临时目录
    pub fn get_pdf_digest_sign_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.pdf_digest_sign_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置pdf签章哈希临时目录
    pub fn set_pdf_digest_sign_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.pdf_digest_sign_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
        match PathBuf::from_str(dir) {
            Ok(dir_path) => {
                if !dir_path.exists() {
                    match std::fs::create_dir_all(dir_path) {
                        Ok(_) => (),
                        Err(err) => logger::error!("error occured when create dir【{}】: {}", dir, err),
                    }
                }
            },
            Err(err) => logger::error!("error occured when convert dir【{}】 to path: {}", dir, err),
        }
    }
    /// 获取pdf验签临时目录
    pub fn get_pdf_verify_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.pdf_verify_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置pdf验签临时目录
    pub fn set_pdf_verify_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.pdf_verify_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
        match PathBuf::from_str(dir) {
            Ok(dir_path) => {
                if !dir_path.exists() {
                    match std::fs::create_dir_all(dir_path) {
                        Ok(_) => (),
                        Err(err) => logger::error!("error occured when create dir【{}】: {}", dir, err),
                    }
                }
            },
            Err(err) => logger::error!("error occured when convert dir【{}】 to path: {}", dir, err),
        }
    }
    /// 获取java执行参数文件目录
    pub fn get_java_args_dir(state: &Arc<Mutex<AppState>>) -> String {
        match state.lock() {
            Ok(app_state) => String::from(&app_state.java_args_dir),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                String::from("")
            }
        }
    }
    /// 设置java执行参数文件目录
    pub fn set_java_args_dir(dir: &str, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.java_args_dir = dir.to_string(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
        match PathBuf::from_str(dir) {
            Ok(dir_path) => {
                if !dir_path.exists() {
                    match std::fs::create_dir_all(dir_path) {
                        Ok(_) => (),
                        Err(err) => logger::error!("error occured when create dir【{}】: {}", dir, err),
                    }
                }
            },
            Err(err) => logger::error!("error occured when convert dir【{}】 to path: {}", dir, err),
        }
    }
    /// 获取用户登录信息
    pub fn get_user_info(state: &Arc<Mutex<AppState>>) -> serde_json::Value {
        match state.lock() {
            Ok(app_state) => app_state.user_info.clone(),
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
                serde_json::json!("")
            }
        }
    }
    /// 设置用户登录信息
    pub fn set_user_info(user_info: serde_json::Value, state: &Arc<Mutex<AppState>>) {
        match state.lock() {
            Ok(mut app_state) => app_state.user_info = user_info,
            Err(err) => {
                logger::error!("try to lock app state failed: {}", err);
            }
        }
    }
    /// 用户退出登录时调用
    pub fn user_logout(state: &Arc<Mutex<AppState>>) {
        AppState::set_user_info(serde_json::json!(""), state);
    }
}