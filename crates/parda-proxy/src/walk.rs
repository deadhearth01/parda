//! Generic JSON walking helpers shared by the provider adapters.
//!
//! A walker visits every redactable string as `&mut String`. Redaction runs
//! it twice in the same order: once to collect the texts (one engine batch),
//! once to write the results back.

use serde_json::Value;

pub(crate) type Visit<'a> = &'a mut dyn FnMut(&mut String);

/// Every string leaf (values, not keys).
pub(crate) fn leaves(v: &mut Value, f: Visit<'_>) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter_mut().for_each(|x| leaves(x, f)),
        Value::Object(m) => m.values_mut().for_each(|x| leaves(x, f)),
        _ => {}
    }
}

/// A JSON document carried as a string (tool-call `arguments`): visit its
/// string leaves and re-serialise it; text that is not a JSON object/array
/// is visited as plain text.
pub(crate) fn json_string(s: &mut String, f: Visit<'_>) {
    match serde_json::from_str::<Value>(s) {
        Ok(mut v) if v.is_object() || v.is_array() => {
            leaves(&mut v, f);
            *s = v.to_string();
        }
        _ => f(s),
    }
}

pub(crate) fn str_field(v: &mut Value, key: &str, f: Visit<'_>) {
    if let Some(Value::String(s)) = v.get_mut(key) {
        f(s);
    }
}

pub(crate) fn type_of(v: &Value) -> &str {
    v.get("type").and_then(Value::as_str).unwrap_or("")
}

/// Collect the texts a walker visits (test helper).
#[cfg(test)]
pub(crate) fn collect(v: &mut Value, walker: impl Fn(&mut Value, Visit<'_>)) -> Vec<String> {
    let mut texts = Vec::new();
    walker(v, &mut |s: &mut String| texts.push(s.clone()));
    texts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn leaves_and_json_strings() {
        let mut v = json!({"a": "x", "b": [1, "y", {"c": "z"}], "k": true});
        let got = collect(&mut v, |v, f| leaves(v, f));
        assert_eq!(got, ["x", "y", "z"]);
        let mut s = String::from(r#"{"to":"ravi@x.in","n":2}"#);
        json_string(&mut s, &mut |t| *t = t.to_uppercase());
        assert_eq!(s, r#"{"to":"RAVI@X.IN","n":2}"#);
        let mut plain = String::from("not json");
        json_string(&mut plain, &mut |t| t.push('!'));
        assert_eq!(plain, "not json!");
    }
}
