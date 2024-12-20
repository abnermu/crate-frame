use serde::{Serialize, Deserialize};
use std::{path::PathBuf, str::FromStr, sync::{Arc, Mutex}};
use tauri::{AppHandle, State, Config};
use crate::AppState;
use log as logger;

/// 响应code
#[repr(i32)]
pub enum ResponseCode {
    /// 响应成功 200
    Success = 200,
    /// 响应失败 500
    Error = 500,
}
/// commands请求响应结果
#[derive(Serialize, Deserialize)]
pub struct Response<T> {
    /// 响应编码
    pub code: i32,
    /// 响应消息
    pub msg: String,
    /// 响应数据
    pub data: Option<T>,
}
impl<T> Response<T> {
    /// 返回成功响应
    pub fn res_ok(data: T) -> Self {
        Response::<T> {
            code: ResponseCode::Success as i32,
            msg: String::from("操作成功！"),
            data: Some(data),
        }
    }
    /// 返回失败响应
    pub fn res_error(msg: &str) -> Self {
        Response::<T> {
            code: ResponseCode::Error as i32,
            msg: msg.to_string(),
            data: None,
        }
    }
}

/// 打开开发者工具
#[tauri::command]
pub fn jy_frame_open_devtool(window: tauri::WebviewWindow) {
    window.open_devtools();
}

/// 获取HTTP端口号
#[tauri::command]
pub fn jy_frame_local_port(state: State<'_, Arc<Mutex<AppState>>>) -> Result<u16, String> {
    let local_port = AppState::get_local_port(&state);
    Ok(if local_port == 0 {20080} else {local_port})
}

/// 获取deeplink插件配置
#[tauri::command]
pub fn jy_frame_config(app: AppHandle) -> Result<Config, String> {
    let config = app.config().clone();
    Ok(config)
}

/// 验证机器码有效性
#[tauri::command]
pub fn jy_frame_machine_code_check(state: State<'_, Arc<Mutex<AppState>>>) -> Result<bool, String> {
    if let Some(machine_code) = crate::SysUtil::get_machine_code() {
        let data_dir = crate::AppState::get_data_dir(&state);
        let lic_dir: PathBuf = [data_dir.as_str(), "lic"].iter().collect();
        if let Ok(files) = std::fs::read_dir(lic_dir) {
            for entry_result in files {
                if let Ok(entry) = entry_result {
                    if crate::SysUtil::license_check(&machine_code, entry.path().to_string_lossy().to_string().as_str()) {
                        return Ok(true);
                    }
                    else {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
        Err(machine_code)
    }
    else {
        Ok(false)
    }
}

/// 导入算码文件
#[tauri::command]
pub fn jy_frame_machine_code_import(state: State<'_, Arc<Mutex<AppState>>>, lic_file: &str) -> Result<bool, String> {
    let data_dir = crate::AppState::get_data_dir(&state);
    let lic_dir: PathBuf = [data_dir.as_str(), "lic"].iter().collect();
    if !lic_dir.exists() {
        if let Err(err) = std::fs::create_dir_all(&lic_dir) {
            logger::error!("failed make lic dir: {:?}", err);
            return Err(String::from("算码文件导入失败"));
        }
    }
    match PathBuf::from_str(lic_file) {
        Ok(src_path) => {
            let file_name = src_path.file_name().unwrap();
            match std::fs::copy(&src_path, &[data_dir.as_str(), "lic", file_name.to_string_lossy().to_string().as_str()].iter().collect::<PathBuf>()) {
                Ok(_) => return Ok(true),
                Err(err) => logger::error!("failed copy lic_file: {:?}", err),
            }
        },
        Err(err) => logger::error!("failed parse lic_file to a pathbuf: {:?}", err),
    }
    Err(String::from("算码文件导入失败"))
}