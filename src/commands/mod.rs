use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, State, Config};
use crate::AppState;

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