use std::sync::{Arc, Mutex};
use tauri::State;

/// 应用状态
#[derive(Default)]
pub struct AppState {
    /// 新点驱动端口号
    pub ep_ca_port: i32,
}
impl AppState {
    /// 初始化数据
    pub fn init() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(AppState::default()))
    }
    /// 获取新点驱动已经测试好的端口号
    pub fn get_ep_ca_port(state: &State<'_, Arc<Mutex<AppState>>>) -> i32 {
        match state.lock() {
            Ok(app_state) => app_state.ep_ca_port,
            Err(..) => 0,
        }
    }
    /// 重新设置新点驱动测试端口号
    pub fn set_ep_ca_port(port: i32, state: &State<'_, Arc<Mutex<AppState>>>) {
        if let Ok(mut app_state) = state.lock() {
            app_state.ep_ca_port = port;
        }
    }
}