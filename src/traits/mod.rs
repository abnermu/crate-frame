use log as logger;
use serde::Serialize;

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