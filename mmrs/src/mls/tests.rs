use super::*;

const EXTERNAL_SENDER: &[u8] = include_bytes!("testdata/external_sender.bin");
const KEY_PACKAGE_A: &[u8] = include_bytes!("testdata/key_package_a.bin");
const KEY_PACKAGE_B: &[u8] = include_bytes!("testdata/key_package_b.bin");
const PROPOSALS: &[u8] = include_bytes!("testdata/proposals.bin");
const COMMIT_WELCOME: &[u8] = include_bytes!("testdata/commit_welcome.bin");
const WELCOME_B: &[u8] = include_bytes!("testdata/welcome_b.bin");

const USER_A: u64 = 100000000000000001;
const USER_B: u64 = 100000000000000002;
const CHANNEL: u64 = 100000000000000010;

/// The op 27 Add of B, split into the signed content and the signature.
struct Add<'a> {
    message: &'a [u8],
    content: &'a [u8],
    signature: &'a [u8],
    key_package: KeyPackage<'a>,
}

fn fixture_add() -> Add<'static> {
    assert_eq!(PROPOSALS[0], 0, "append");
    let mut outer = TlsReader::new(&PROPOSALS[1..]);
    let message = outer.vector().unwrap();
    assert!(outer.is_empty());

    let mut reader = TlsReader::new(message);
    assert_eq!(reader.u16(), Some(MLS10));
    assert_eq!(reader.u16(), Some(WIRE_FORMAT_PUBLIC));
    let content_start = reader.position();
    assert_eq!(reader.vector(), Some(&CHANNEL.to_be_bytes()[..]));
    assert_eq!(reader.u64(), Some(0));
    assert_eq!(reader.u8(), Some(SENDER_EXTERNAL));
    assert_eq!(reader.u32(), Some(0));
    assert_eq!(reader.vector(), Some(&[][..]));
    assert_eq!(reader.u8(), Some(CONTENT_PROPOSAL));
    assert_eq!(reader.u16(), Some(PROPOSAL_ADD));
    let key_package = KeyPackage::read(&mut reader).unwrap();
    let content = reader.since(content_start);
    let signature = reader.vector().unwrap();
    assert!(reader.is_empty());

    Add {
        message,
        content,
        signature,
        key_package,
    }
}

#[test]
fn validates_client_key_packages() {
    let key_package = KeyPackage::parse(KEY_PACKAGE_A).unwrap();
    assert_eq!(key_package.validate(USER_A), Ok(()));
    assert_eq!(
        key_package.validate(USER_B),
        Err(Invalid("identity is not the session's user"))
    );

    let mut tampered = KEY_PACKAGE_A.to_vec();
    let last = tampered.len() - 10;
    tampered[last] ^= 1;
    let tampered = KeyPackage::parse(&tampered).unwrap();
    assert_eq!(
        tampered.validate(USER_A),
        Err(Invalid("key package signature"))
    );

    assert_eq!(fixture_add().key_package.raw, KEY_PACKAGE_B);
}

#[test]
fn external_add_signature_verifies() {
    let add = fixture_add();
    let mut reader = TlsReader::new(EXTERNAL_SENDER);
    let key = reader.vector().unwrap();

    let mut tbs = TlsWriter::default();
    tbs.u16(MLS10).u16(WIRE_FORMAT_PUBLIC).bytes(add.content);
    let tbs = tbs.into_bytes();
    assert!(verify_with_label(
        key,
        "FramedContentTBS",
        &tbs,
        add.signature
    ));
    assert!(!verify_with_label(key, "LeafNodeTBS", &tbs, add.signature));
}

#[test]
fn commit_references_the_proposal() {
    let add = fixture_add();
    let (commit, welcome) = parse_commit_welcome(COMMIT_WELCOME).unwrap();
    assert_eq!(commit.group_id, CHANNEL.to_be_bytes());
    assert_eq!(commit.epoch, 0);
    assert_eq!(commit.sender_leaf, 0);
    assert_eq!(commit.raw[..4], [0, 1, 0, 1]);
    assert!(commit.path_leaf.is_none());

    let reference = ref_hash("MLS 1.0 Proposal Reference", &add.message[2..]);
    assert_eq!(commit.proposal_refs, [&reference[..]]);

    let welcome = welcome.unwrap();
    let b = add.key_package.reference();
    assert_eq!(welcome.new_members().collect::<Vec<_>>(), [&b[..]]);
    assert_eq!(welcome.for_member(&b).unwrap(), WELCOME_B);
    assert!(welcome.for_member(&[0; 32]).is_none());
}

#[test]
fn rejects_trailing_bytes() {
    let mut data = COMMIT_WELCOME.to_vec();
    data.push(0);
    assert!(parse_commit_welcome(&data).is_none());

    let mut data = KEY_PACKAGE_A.to_vec();
    data.push(0);
    assert!(KeyPackage::parse(&data).is_none());
}

#[test]
fn external_sender_encoding() {
    let sender = ExternalSender::generate();
    let mut reader = TlsReader::new(&sender.encoded);
    assert_eq!(reader.vector().unwrap().len(), 65);
    assert_eq!(reader.u16(), Some(BASIC_CREDENTIAL));
    assert_eq!(reader.vector(), Some(&[0][..]));
    assert!(reader.is_empty());
    assert_eq!(sender.encoded.len(), EXTERNAL_SENDER.len());
}

#[test]
fn proposal_bodies() {
    let sender = ExternalSender::generate();
    let remove = sender.remove(&[1; 8], 3, 2);
    let body = proposals_append([remove.message.as_slice()]);
    assert_eq!(body[0], 0);
    assert_eq!(TlsReader::new(&body[1..]).vector().unwrap(), remove.message);

    let body = proposals_revoke([&remove.reference]);
    let mut reader = TlsReader::new(&body[1..]);
    let refs = reader.items(TlsReader::vector).unwrap();
    assert_eq!(body[0], 1);
    assert_eq!(refs, [&remove.reference[..]]);
}
