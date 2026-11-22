#[cfg(test)]
mod tests {
    use super::super::dns::*;

    #[test]
    fn test_dns_constants() {
        assert_eq!(RR_TYPE_A, 1);
        assert_eq!(RR_TYPE_NS, 2);
        assert_eq!(RR_TYPE_CNAME, 5);
        assert_eq!(RR_TYPE_TXT, 16);
        assert_eq!(RR_TYPE_AAAA, 28);
        assert_eq!(RR_TYPE_OPT, 41);
        assert_eq!(CLASS_IN, 1);
        assert_eq!(RCODE_NO_ERROR, 0);
        assert_eq!(RCODE_FORMAT_ERROR, 1);
        assert_eq!(RCODE_NAME_ERROR, 3);
        assert_eq!(RCODE_NOT_IMPLEMENTED, 4);
    }

    #[test]
    fn test_name_validation_and_display() {
        let root = Name::new(vec![]).unwrap();
        assert_eq!(root.to_string(), ".");

        let n = Name::new(vec![b"example".to_vec(), b"com".to_vec()]).unwrap();
        assert_eq!(n.to_string(), "example.com");

        assert!(Name::new(vec![b"".to_vec()]).is_err());
        assert!(Name::new(vec![b"a".to_vec(), b"".to_vec(), b"c".to_vec()]).is_err());

        let label63 = vec![b'a'; 63];
        assert!(Name::new(vec![label63]).is_ok());

        let label64 = vec![b'a'; 64];
        assert!(Name::new(vec![label64]).is_err());

        let labels_huge = vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 63],
        ];
        assert!(Name::new(labels_huge).is_err());

        let special = Name::new(vec![vec![0x00, 0x1f, b'a', b'-', 0xff]]).unwrap();
        assert_eq!(special.to_string(), "\\x00\\x1fa-\\xff");
    }

    #[test]
    fn test_name_parse_and_trim_suffix() {
        let name = Name::parse("tunnel.client.example.com").unwrap();
        assert_eq!(name.to_string(), "tunnel.client.example.com");

        let suffix = Name::parse("example.com").unwrap();
        let trimmed = name.trim_suffix(&suffix).expect("Should trim suffix");
        assert_eq!(trimmed.to_string(), "tunnel.client");

        let upper_suffix = Name::parse("EXAMPLE.COM").unwrap();
        let trimmed_upper = name
            .trim_suffix(&upper_suffix)
            .expect("Should trim case-insensitively");
        assert_eq!(trimmed_upper.to_string(), "tunnel.client");

        let non_matching = Name::parse("other.org").unwrap();
        assert!(name.trim_suffix(&non_matching).is_none());
    }

    #[test]
    fn test_encode_decode_rdata_txt() {
        assert!(decode_rdata_txt(&[]).is_err());

        let decoded_empty = decode_rdata_txt(&[0]).unwrap();
        assert!(decoded_empty.is_empty());

        let data = b"Hello, XDNS Wire Tunnel!";
        let encoded = encode_rdata_txt(data);
        assert_eq!(encoded[0], data.len() as u8);
        assert_eq!(&encoded[1..], data);
        let decoded = decode_rdata_txt(&encoded).unwrap();
        assert_eq!(decoded, data);

        let mut large_data = Vec::with_capacity(600);
        for i in 0..600 {
            large_data.push((i % 256) as u8);
        }
        let encoded_large = encode_rdata_txt(&large_data);
        assert_eq!(encoded_large[0], 255);
        assert_eq!(encoded_large[256], 255);
        assert_eq!(encoded_large[512], 90);
        let decoded_large = decode_rdata_txt(&encoded_large).unwrap();
        assert_eq!(decoded_large, large_data);

        let all_bytes: Vec<u8> = (0..=255).collect();
        let encoded_all = encode_rdata_txt(&all_bytes);
        let decoded_all = decode_rdata_txt(&encoded_all).unwrap();
        assert_eq!(decoded_all, all_bytes);
    }

    #[test]
    fn test_base32_rfc4648_test_vectors() {

        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");

        assert_eq!(base32_decode("").unwrap(), b"");
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("mzxq").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode("mzxw6yq").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
    }

    #[test]
    fn test_dns_message_pack_unpack_compression() {
        let mut msg = Message::new();
        msg.id = 0x4321;
        msg.flags = 0x8180;

        let q_name = Name::parse("client.data.tunnel.example.com").unwrap();
        msg.questions.push(Question {
            name: q_name.clone(),
            qtype: RR_TYPE_TXT,
            qclass: CLASS_IN,
        });

        msg.answers.push(ResourceRecord {
            name: q_name.clone(),
            rrtype: RR_TYPE_TXT,
            class: CLASS_IN,
            ttl: 300,
            data: encode_rdata_txt(b"response-data"),
        });

        let wire = msg.pack().expect("pack should succeed");
        let has_compression = wire.windows(2).any(|w| (w[0] & 0xc0) == 0xc0);
        assert!(
            has_compression,
            "Wire format should contain compression pointer"
        );

        let unpacked = Message::unpack(&wire).expect("unpack should succeed");
        assert_eq!(unpacked.id, 0x4321);
        assert_eq!(unpacked.questions.len(), 1);
        assert_eq!(
            unpacked.questions[0].name.to_string(),
            "client.data.tunnel.example.com"
        );
        assert_eq!(unpacked.answers.len(), 1);
        assert_eq!(
            unpacked.answers[0].name.to_string(),
            "client.data.tunnel.example.com"
        );
        assert_eq!(
            decode_rdata_txt(&unpacked.answers[0].data).unwrap(),
            b"response-data"
        );
    }
}
