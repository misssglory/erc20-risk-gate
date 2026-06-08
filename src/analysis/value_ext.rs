use serde_json::Value;

pub fn bool_at(v: &Value, path: &[&str]) -> Option<bool> {
    let mut cur = v;

    for key in path {
        cur = cur.get(*key)?;
    }

    value_to_bool(cur)
}

pub fn string_bool_at(v: &Value, path: &[&str]) -> Option<bool> {
    bool_at(v, path)
}

pub fn number_at(v: &Value, path: &[&str]) -> Option<f64> {
    let mut cur = v;

    for key in path {
        cur = cur.get(*key)?;
    }

    match cur {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

pub fn recursive_bool(v: &Value, wanted_key: &str) -> Option<bool> {
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                if key == wanted_key {
                    return value_to_bool(value);
                }

                if let Some(found) = recursive_bool(value, wanted_key) {
                    return Some(found);
                }
            }

            None
        }
        Value::Array(items) => {
            for item in items {
                if let Some(found) = recursive_bool(item, wanted_key) {
                    return Some(found);
                }
            }

            None
        }
        _ => None,
    }
}

pub fn recursive_number(v: &Value, wanted_key: &str) -> Option<f64> {
    match v {
        Value::Object(map) => {
            for (key, value) in map {
                if key == wanted_key {
                    return value_to_number(value);
                }

                if let Some(found) = recursive_number(value, wanted_key) {
                    return Some(found);
                }
            }

            None
        }
        Value::Array(items) => {
            for item in items {
                if let Some(found) = recursive_number(item, wanted_key) {
                    return Some(found);
                }
            }

            None
        }
        _ => None,
    }
}

pub fn first_goplus_token(v: &Value) -> Option<&Value> {
    v.get("result")
        .and_then(|r| r.as_object())
        .and_then(|map| map.values().next())
}

pub fn value_to_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_i64()? == 1),
        Value::String(s) => {
            let s = s.trim().to_lowercase();

            match s.as_str() {
                "1" | "true" | "yes" => Some(true),
                "0" | "false" | "no" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn value_to_number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}