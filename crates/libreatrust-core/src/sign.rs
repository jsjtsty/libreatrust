use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn calc_request_sig(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    hex::encode_upper(out)
}

#[cfg(test)]
mod tests {
    use super::calc_request_sig;

    #[test]
    fn produces_stable_hmac_sha256_uppercase_hex() {
        assert_eq!(
            calc_request_sig(b"0123456789abcdef", b"abc"),
            "BCAA92843247BC258080D2824BDDEBA4AFB1BD61B4688CA65F60A214E1D9759E"
        );
    }
}
