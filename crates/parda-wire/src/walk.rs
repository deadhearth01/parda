//! Generic JSON walking helpers: string leaves, JSON carried in strings, and
//! number literals kept as written when a document is re-serialised.
//!
//! A walker visits every redactable string as `&mut String`. Redaction runs
//! it twice in the same order: once to collect the texts (one engine batch),
//! once to write the results back.

use serde_json::Value;

pub type Visit<'a> = &'a mut dyn FnMut(&mut String);

/// Every string leaf (values, not keys).
pub fn leaves(v: &mut Value, f: Visit<'_>) {
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
pub fn json_string(s: &mut String, f: Visit<'_>) {
    match serde_json::from_str::<Value>(s) {
        Ok(mut v) if v.is_object() || v.is_array() => {
            leaves(&mut v, f);
            let out = preserve_numbers(s.as_bytes(), v.to_string().into_bytes());
            *s = String::from_utf8(out)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        }
        _ => f(s),
    }
}

/// Byte ranges of the number literals of a JSON text, outside strings.
fn number_tokens(json: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut in_string = false;
    while i < json.len() {
        let b = json[i];
        if in_string {
            match b {
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
        } else if b == b'-' || b.is_ascii_digit() {
            let start = i;
            while i < json.len()
                && matches!(json[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                i += 1;
            }
            out.push((start, i));
        } else {
            i += 1;
        }
    }
    out
}

/// serde_json (without `arbitrary_precision`) turns integers beyond 64 bits
/// into floats and respells some floats (`1e-1` → `0.1`). Put the
/// original literals back into `out`, a re-serialisation of `original`,
/// wherever the two denote the same value: redaction only rewrites
/// strings, so numbers appear in the same order (a body whose numbers do
/// not line up — duplicate keys — is left as re-serialised).
pub fn preserve_numbers(original: &[u8], out: Vec<u8>) -> Vec<u8> {
    let before = number_tokens(original);
    let after = number_tokens(&out);
    if before.len() != after.len() {
        return out;
    }
    let as_f64 = |t: &[u8]| std::str::from_utf8(t).ok()?.parse::<f64>().ok();
    let mut fixed = Vec::with_capacity(out.len());
    let mut last = 0;
    for (&(bs, be), &(as_, ae)) in before.iter().zip(&after) {
        let (orig, now) = (&original[bs..be], &out[as_..ae]);
        if orig == now || as_f64(orig).is_none() || as_f64(orig) != as_f64(now) {
            continue;
        }
        fixed.extend_from_slice(&out[last..as_]);
        fixed.extend_from_slice(orig);
        last = ae;
    }
    if last == 0 {
        return out;
    }
    fixed.extend_from_slice(&out[last..]);
    fixed
}

pub fn str_field(v: &mut Value, key: &str, f: Visit<'_>) {
    if let Some(Value::String(s)) = v.get_mut(key) {
        f(s);
    }
}

pub fn type_of(v: &Value) -> &str {
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
    fn number_literals_are_preserved() {
        let orig =
            br#"{"a":123456789012345678901234567890,"s":"1e5 \"9\"","b":[1e-1,-0.0,2],"c":1.0}"#;
        let v: Value = serde_json::from_slice(orig).unwrap();
        let out = preserve_numbers(orig, serde_json::to_vec(&v).unwrap());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            String::from_utf8(orig.to_vec()).unwrap()
        );
        // Duplicate keys: numbers no longer line up; nothing is swapped.
        let orig = br#"{"a":"x","b":1,"a":2}"#;
        let v: Value = serde_json::from_slice(orig).unwrap();
        let re = serde_json::to_vec(&v).unwrap();
        assert_eq!(preserve_numbers(orig, re.clone()), re);
    }

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
