use log as logger;
use serde::Serialize;

/// 通用的签章后结构体定义一些get set方法
pub trait SingOut {
    fn set_file_path(&mut self, file_path: &str);
    fn get_file_path(&self) -> String;
    fn set_file_url(&mut self, file_url: &str);
    fn get_file_url(&self) -> String;
    fn set_file_base64(&mut self, file_base64: &str);
    fn get_file_base64(&self) -> String;
    fn set_out_resp(&mut self, out_resp: &str);
    fn get_out_resp(&self) -> String;
}
/// 把struct转为json对象的通用trait
pub trait JsonOut {
    /// struct转为json对象
    fn to_json(&self) -> serde_json::Value 
    where Self: Serialize
    {
        match serde_json::to_string(&self) {
            Ok(json_str) => {
                match serde_json::from_str::<serde_json::Value>(json_str.as_str()) {
                    Ok(json_obj) => {
                        return json_obj.clone();
                    },
                    Err(err) => {
                        logger::error!("error occured when convert json string to json object: {}", err);
                    }
                }
            },
            Err(err) => {
                logger::error!("error occured when convert struct to json string: {}", err);
            },
        }
        serde_json::json!({})
    }
}