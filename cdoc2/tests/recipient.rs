use cdoc2::capsule::ecc::{EcPublicKey, EcSecretKey};
use cdoc2::container::Container;
use cdoc2::encrypt::{EncryptError, Recipient, encrypt, prepare};
use cdoc2::header::RecipientId;
use cdoc2::key_label;

fn ec_public_key(byte: u8) -> EcPublicKey {
    EcSecretKey::P256(p256::SecretKey::from_slice(&[byte; 32]).unwrap()).public_key()
}

#[test]
fn find_recipient() {
    let ec_key = ec_public_key(1);
    let structured_label = key_label::symmetric("structured");
    let recipients = [
        Recipient::Symmetric {
            key_label: &structured_label,
            key: &[1; 32],
        },
        Recipient::Symmetric {
            key_label: "plain",
            key: &[2; 32],
        },
        Recipient::EcPublicKey {
            key_label: "ec",
            public_key: &ec_key,
        },
    ];
    let bytes = encrypt(&[], &recipients).unwrap();
    let container = Container::parse(&bytes).unwrap();

    let other_ec_key = ec_public_key(2);
    let structured = structured_label.as_str();
    let cases = [
        // A structured label matches by its label field or as a whole.
        (
            RecipientId::Symmetric {
                label: "structured",
            },
            Some(structured),
        ),
        (
            RecipientId::Symmetric { label: structured },
            Some(structured),
        ),
        (RecipientId::Symmetric { label: "plain" }, Some("plain")),
        (RecipientId::EcPublicKey(&ec_key), Some("ec")),
        // A label only matches recipients of its own kind.
        (
            RecipientId::Password {
                label: "structured",
            },
            None,
        ),
        (RecipientId::Symmetric { label: "ec" }, None),
        // Unknown labels and keys aren't found.
        (RecipientId::Symmetric { label: "other" }, None),
        (RecipientId::EcPublicKey(&other_ec_key), None),
    ];
    for (id, expected) in cases {
        let found = container.head.header.find_recipient(id);
        assert_eq!(
            found.ok().map(|record| record.key_label.as_str()),
            expected,
            "{id:?}"
        );
    }
}

#[test]
fn debug_redacts_secrets() {
    let symmetric = Recipient::Symmetric {
        key_label: "label",
        key: b"secret key",
    };
    let password = Recipient::Password {
        key_label: "label",
        password: "hunter2",
    };
    assert_eq!(
        format!("{symmetric:?}"),
        r#"Symmetric { key_label: "label", key: [redacted] }"#
    );
    assert_eq!(
        format!("{password:?}"),
        r#"Password { key_label: "label", password: [redacted] }"#
    );
}

#[test]
fn weak_secrets() {
    let check = |recipient| prepare(&[recipient]).err();
    let key = |key| Recipient::Symmetric {
        key_label: "label",
        key,
    };
    assert_eq!(
        check(key(&[1; 31])),
        Some(EncryptError::KeyTooShort("label".into()))
    );
    assert_eq!(check(key(&[1; 32])), None);

    let password = |password| Recipient::Password {
        key_label: "label",
        password,
    };
    // The length restriction is on the character count, and not byte count.
    let nineteen_chars = "õ".repeat(19); // õ takes 2 bytes
    assert_eq!(
        check(password(&nineteen_chars)),
        Some(EncryptError::PasswordTooShort("label".into()))
    );
}
