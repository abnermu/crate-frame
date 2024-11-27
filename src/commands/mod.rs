use serde::{Serialize, Deserialize};

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