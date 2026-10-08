//! Parameters in, values out (§6.7 step 6).
//!
//! **Parameters** are always sent in **text format** ([`TextParam`]): the server parses each one
//! for the type it inferred, so a parameter is never SQL and never needs a Rust type per column.
//!
//! **Results** are decoded by [`AnyValue`], which accepts every type:
//! - `int8` and `numeric` become strings (JSON numbers lose precision above 2^53)
//! - float NaN and ±Infinity, numeric NaN and ±Infinity, and infinite dates and timestamps become
//!   strings
//! - `json`/`jsonb` are embedded; `bytea` is base64; arrays (any number of dimensions) become
//!   nested JSON arrays
//! - anything else becomes `{"type", "hex"}`, or just its size when it's large; the cap applies
//!   before hex-encoding

use std::error::Error;

use base64::Engine;
use serde_json::{Value, json};
use tokio_postgres::types::{Format, FromSql, IsNull, Kind, ToSql, Type, to_sql_checked};

type BoxError = Box<dyn Error + Sync + Send>;

/// The largest unknown-type value shown as hex.
const MAX_HEX_BYTES: usize = 4 * 1024;

/// A parameter sent in text format; `None` is SQL NULL.
#[derive(Debug, Clone)]
pub struct TextParam(pub Option<String>);

impl TextParam {
    /// Converts a JSON parameter. Strings with NUL bytes are refused (Postgres text can't hold them).
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let text = match v {
            Value::Null => return Ok(Self(None)),
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        };
        if text.contains('\0') {
            return Err("parameters can't contain NUL characters".into());
        }
        Ok(Self(Some(text)))
    }
}

impl ToSql for TextParam {
    fn to_sql(&self, _ty: &Type, out: &mut tokio_postgres::types::private::BytesMut) -> Result<IsNull, BoxError> {
        match &self.0 {
            None => Ok(IsNull::Yes),
            Some(s) => {
                out.extend_from_slice(s.as_bytes());
                Ok(IsNull::No)
            }
        }
    }

    fn accepts(_: &Type) -> bool {
        true
    }

    fn encode_format(&self, _ty: &Type) -> Format {
        Format::Text
    }

    to_sql_checked!();
}

/// Any result value, as JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct AnyValue(pub Value);

impl<'a> FromSql<'a> for AnyValue {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, BoxError> {
        Ok(Self(decode(ty, raw)))
    }

    fn from_sql_null(_: &Type) -> Result<Self, BoxError> {
        Ok(Self(Value::Null))
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

/// Decodes a binary-format value. Never fails: anything unexpected becomes the fallback.
pub fn decode(ty: &Type, raw: &[u8]) -> Value {
    try_decode(ty, raw).unwrap_or_else(|| fallback(ty, raw))
}

fn try_decode(ty: &Type, raw: &[u8]) -> Option<Value> {
    match ty.kind() {
        Kind::Array(member) => return decode_array(member, raw),
        Kind::Domain(base) => return Some(decode(base, raw)),
        Kind::Enum(_) => return std::str::from_utf8(raw).ok().map(|s| json!(s)),
        _ => {}
    }
    Some(match *ty {
        Type::BOOL => json!(*raw.first()? != 0),
        Type::INT2 => json!(i16::from_be_bytes(raw.try_into().ok()?)),
        Type::INT4 => json!(i32::from_be_bytes(raw.try_into().ok()?)),
        Type::OID => json!(u32::from_be_bytes(raw.try_into().ok()?)),
        Type::INT8 => json!(i64::from_be_bytes(raw.try_into().ok()?).to_string()),
        Type::FLOAT4 => float(f64::from(f32::from_be_bytes(raw.try_into().ok()?))),
        Type::FLOAT8 => float(f64::from_be_bytes(raw.try_into().ok()?)),
        Type::NUMERIC => json!(numeric(raw)?),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME | Type::UNKNOWN | Type::CHAR => {
            json!(std::str::from_utf8(raw).ok()?)
        }
        Type::JSON => serde_json::from_slice(raw).ok()?,
        Type::JSONB => serde_json::from_slice(raw.strip_prefix(&[1])?).ok()?,
        Type::UUID => json!(uuid(raw)?),
        Type::BYTEA => json!(base64::engine::general_purpose::STANDARD.encode(raw)),
        Type::DATE => json!(date(i32::from_be_bytes(raw.try_into().ok()?))),
        Type::TIME => json!(time(i64::from_be_bytes(raw.try_into().ok()?))?),
        Type::TIMESTAMP => json!(timestamp(i64::from_be_bytes(raw.try_into().ok()?), false)),
        Type::TIMESTAMPTZ => json!(timestamp(i64::from_be_bytes(raw.try_into().ok()?), true)),
        _ => return None,
    })
}

fn fallback(ty: &Type, raw: &[u8]) -> Value {
    if raw.len() > MAX_HEX_BYTES {
        return json!({ "type": ty.name(), "bytes": raw.len(), "omitted": "too large to show" });
    }
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    json!({ "type": ty.name(), "hex": hex })
}

fn float(f: f64) -> Value {
    if f.is_nan() {
        json!("NaN")
    } else if f.is_infinite() {
        json!(if f > 0.0 { "Infinity" } else { "-Infinity" })
    } else {
        json!(f)
    }
}

/// Postgres's binary numeric: ndigits, weight, sign, dscale, then base-10000 digits.
fn numeric(raw: &[u8]) -> Option<String> {
    let word = |i: usize| -> Option<u16> { Some(u16::from_be_bytes(raw.get(i..i + 2)?.try_into().ok()?)) };
    let ndigits = word(0)? as usize;
    let weight = word(2)? as i16;
    let sign = word(4)?;
    let dscale = word(6)? as usize;
    match sign {
        0xC000 => return Some("NaN".into()),
        0xD000 => return Some("Infinity".into()),
        0xF000 => return Some("-Infinity".into()),
        0x0000 | 0x4000 => {}
        _ => return None,
    }
    let digits: Vec<u16> = (0..ndigits).map(|i| word(8 + 2 * i)).collect::<Option<_>>()?;
    if digits.iter().any(|d| *d > 9999) {
        return None;
    }
    // Integer part: base-10000 digits with index <= weight.
    let mut int = String::new();
    if weight < 0 {
        int.push('0');
    } else {
        for i in 0..=weight as usize {
            let d = digits.get(i).copied().unwrap_or(0);
            if int.is_empty() {
                int.push_str(&d.to_string());
            } else {
                int.push_str(&format!("{d:04}"));
            }
        }
    }
    // Fraction: the digits after the weight, padded, cut to dscale.
    let mut frac = String::new();
    if dscale > 0 {
        let first = weight + 1;
        let mut i = first;
        while frac.len() < dscale {
            let d = if i < 0 {
                0
            } else {
                digits.get(i as usize).copied().unwrap_or(0)
            };
            frac.push_str(&format!("{d:04}"));
            i += 1;
        }
        frac.truncate(dscale);
    }
    let mut out = String::new();
    if sign == 0x4000 {
        out.push('-');
    }
    out.push_str(&int);
    if !frac.is_empty() {
        out.push('.');
        out.push_str(&frac);
    }
    Some(out)
}

fn uuid(raw: &[u8]) -> Option<String> {
    if raw.len() != 16 {
        return None;
    }
    let h: Vec<String> = raw.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    ))
}

fn epoch() -> chrono::NaiveDateTime {
    chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
        .expect("valid")
        .and_hms_opt(0, 0, 0)
        .expect("valid")
}

fn date(days: i32) -> String {
    match days {
        i32::MAX => "infinity".into(),
        i32::MIN => "-infinity".into(),
        d => epoch()
            .date()
            .checked_add_signed(chrono::Duration::days(i64::from(d)))
            .map_or_else(|| format!("{d} days from 2000-01-01"), |dt| dt.to_string()),
    }
}

fn time(micros: i64) -> Option<String> {
    let secs = u32::try_from(micros / 1_000_000).ok()?;
    let nanos = u32::try_from((micros % 1_000_000) * 1000).ok()?;
    chrono::NaiveTime::from_num_seconds_from_midnight_opt(secs, nanos).map(|t| t.format("%H:%M:%S%.f").to_string())
}

fn timestamp(micros: i64, tz: bool) -> String {
    match micros {
        i64::MAX => return "infinity".into(),
        i64::MIN => return "-infinity".into(),
        _ => {}
    }
    match epoch().checked_add_signed(chrono::Duration::microseconds(micros)) {
        Some(dt) if tz => dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string(),
        None => format!("{micros} µs from 2000-01-01"),
    }
}

/// Binary array: ndim, has_nulls, element oid, (len, lower bound) per dimension, then elements
/// (length -1 = NULL). Becomes nested JSON arrays.
fn decode_array(member: &Type, raw: &[u8]) -> Option<Value> {
    let int = |i: usize| -> Option<i32> { Some(i32::from_be_bytes(raw.get(i..i + 4)?.try_into().ok()?)) };
    let ndim = usize::try_from(int(0)?).ok()?;
    if ndim == 0 {
        return Some(json!([]));
    }
    if ndim > 6 {
        return None;
    }
    let dims: Vec<usize> = (0..ndim)
        .map(|d| int(12 + 8 * d).and_then(|n| usize::try_from(n).ok()))
        .collect::<Option<_>>()?;
    let mut pos = 12 + 8 * ndim;
    let total: usize = dims.iter().try_fold(1usize, |acc, d| acc.checked_mul(*d))?;
    let mut flat = Vec::with_capacity(total.min(100_000));
    for _ in 0..total {
        let len = int(pos)?;
        pos += 4;
        if len < 0 {
            flat.push(Value::Null);
        } else {
            let len = len as usize;
            flat.push(decode(member, raw.get(pos..pos + len)?));
            pos += len;
        }
    }
    Some(nest(&dims, &mut flat.into_iter()))
}

fn nest(dims: &[usize], items: &mut impl Iterator<Item = Value>) -> Value {
    match dims {
        [] => items.next().unwrap_or(Value::Null),
        [n] => Value::Array(items.take(*n).collect()),
        [n, rest @ ..] => Value::Array((0..*n).map(|_| nest(rest, items)).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(ndigits: &[u16], weight: i16, sign: u16, dscale: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend((ndigits.len() as u16).to_be_bytes());
        b.extend(weight.to_be_bytes());
        b.extend(sign.to_be_bytes());
        b.extend(dscale.to_be_bytes());
        for d in ndigits {
            b.extend(d.to_be_bytes());
        }
        b
    }

    #[test]
    fn numerics_decode_exactly() {
        assert_eq!(numeric(&num(&[1, 2345, 6700], 1, 0, 2)).unwrap(), "12345.67");
        assert_eq!(numeric(&num(&[5000], -1, 0x4000, 1)).unwrap(), "-0.5");
        assert_eq!(numeric(&num(&[], 0, 0, 0)).unwrap(), "0");
        assert_eq!(
            numeric(&num(&[9007, 1992, 5474, 993], 3, 0, 0)).unwrap(),
            "9007199254740993"
        );
        assert_eq!(numeric(&num(&[1200], -2, 0, 6)).unwrap(), "0.000012");
        assert_eq!(
            numeric(&num(&[12], -2, 0, 6)).unwrap(),
            "0.000000",
            "0.00000012 at scale 6"
        );
        assert_eq!(numeric(&num(&[], 0, 0xC000, 0)).unwrap(), "NaN");
        assert_eq!(numeric(&num(&[], 0, 0xD000, 0)).unwrap(), "Infinity");
    }

    #[test]
    fn big_ints_and_special_floats_are_strings() {
        assert_eq!(
            decode(&Type::INT8, &9_007_199_254_740_993i64.to_be_bytes()),
            json!("9007199254740993")
        );
        assert_eq!(decode(&Type::INT4, &42i32.to_be_bytes()), json!(42));
        assert_eq!(decode(&Type::FLOAT8, &f64::NAN.to_be_bytes()), json!("NaN"));
        assert_eq!(
            decode(&Type::FLOAT4, &f32::NEG_INFINITY.to_be_bytes()),
            json!("-Infinity")
        );
        assert_eq!(decode(&Type::FLOAT8, &1.5f64.to_be_bytes()), json!(1.5));
    }

    #[test]
    fn dates_and_times() {
        assert_eq!(decode(&Type::DATE, &0i32.to_be_bytes()), json!("2000-01-01"));
        assert_eq!(decode(&Type::DATE, &i32::MAX.to_be_bytes()), json!("infinity"));
        assert_eq!(
            decode(&Type::TIMESTAMP, &1_500_000i64.to_be_bytes()),
            json!("2000-01-01T00:00:01.500")
        );
        assert_eq!(
            decode(&Type::TIMESTAMPTZ, &0i64.to_be_bytes()),
            json!("2000-01-01T00:00:00Z")
        );
        assert_eq!(decode(&Type::TIMESTAMPTZ, &i64::MIN.to_be_bytes()), json!("-infinity"));
        assert_eq!(
            decode(&Type::TIME, &(3_600_000_000i64 + 1).to_be_bytes()),
            json!("01:00:00.000001")
        );
    }

    #[test]
    fn json_uuid_bytea_and_text() {
        assert_eq!(decode(&Type::JSONB, b"\x01{\"a\":[1,2]}"), json!({"a": [1, 2]}));
        assert_eq!(
            decode(&Type::UUID, &[0x12; 16]),
            json!("12121212-1212-1212-1212-121212121212")
        );
        assert_eq!(decode(&Type::BYTEA, b"hi"), json!("aGk="));
        assert_eq!(decode(&Type::TEXT, "äö".as_bytes()), json!("äö"));
    }

    #[test]
    fn arrays_nest_with_nulls() {
        // int4[][] = {{1,NULL},{3,4}}
        let mut raw = Vec::new();
        for v in [2i32, 1, 23, 2, 1, 2, 1] {
            raw.extend(v.to_be_bytes());
        }
        for e in [Some(1i32), None, Some(3), Some(4)] {
            match e {
                Some(v) => {
                    raw.extend(4i32.to_be_bytes());
                    raw.extend(v.to_be_bytes());
                }
                None => raw.extend((-1i32).to_be_bytes()),
            }
        }
        assert_eq!(decode(&Type::INT4_ARRAY, &raw), json!([[1, null], [3, 4]]));
    }

    #[test]
    fn unknown_types_fall_back_with_a_cap() {
        assert_eq!(decode(&Type::INET, &[1, 2]), json!({ "type": "inet", "hex": "0102" }));
        let big = vec![0u8; MAX_HEX_BYTES + 1];
        assert_eq!(decode(&Type::INET, &big)["omitted"], json!("too large to show"));
        // Malformed input of a known type falls back instead of failing.
        assert_eq!(decode(&Type::INT4, &[1, 2])["type"], json!("int4"));
    }

    #[test]
    fn json_params_become_text() {
        assert_eq!(TextParam::from_json(&json!(5)).unwrap().0.as_deref(), Some("5"));
        assert_eq!(
            TextParam::from_json(&json!("x'); DROP TABLE t; --"))
                .unwrap()
                .0
                .as_deref(),
            Some("x'); DROP TABLE t; --")
        );
        assert_eq!(TextParam::from_json(&json!(null)).unwrap().0, None);
        assert_eq!(
            TextParam::from_json(&json!({"a": 1})).unwrap().0.as_deref(),
            Some("{\"a\":1}")
        );
        assert!(TextParam::from_json(&json!("a\u{0}b")).is_err());
    }
}
