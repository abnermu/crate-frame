
/// 打开开发者工具
#[tauri::command]
pub fn jy_frame_open_devtool(window: tauri::WebviewWindow) {
    window.open_devtools();
}