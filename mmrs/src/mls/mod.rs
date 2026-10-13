mod codec;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use codec::{TlsReader, TlsWriter};

const MLS10: u16 = 1;
/// MLS_128_DHKEMP256_AES128GCM_SHA256_P256, the only suite DAVE uses.
const CIPHER_SUITE: u16 = 2;
const BASIC_CREDENTIAL: u16 = 1;

const WIRE_FORMAT_PUBLIC: u16 = 1;
const SENDER_MEMBER: u8 = 1;
const SENDER_EXTERNAL: u8 = 2;
const CONTENT_PROPOSAL: u8 = 2;
const CONTENT_COMMIT: u8 = 3;
const PROPOSAL_ADD: u16 = 1;
const PROPOSAL_REMOVE: u16 = 3;
const PROPOSAL_OR_REF_REFERENCE: u8 = 2;

const LEAF_SOURCE_KEY_PACKAGE: u8 = 1;
const LEAF_SOURCE_UPDATE: u8 = 2;
const LEAF_SOURCE_COMMIT: u8 = 3;

/// `opaque HashReference<V>`: KeyPackageRef and ProposalRef.
pub type Ref = [u8; 32];

#[derive(Debug, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

pub struct LeafNode<'a> {
    pub encryption_key: &'a [u8],
    pub signature_key: &'a [u8],
    /// The basic credential's identity: a user ID as 8 big-endian bytes.
    pub identity: &'a [u8],
    cipher_suites: Vec<u16>,
    credentials: Vec<u16>,
    lifetime: Option<(u64, u64)>,
    tbs: &'a [u8],
    signature: &'a [u8],
}

impl<'a> LeafNode<'a> {
    fn parse(reader: &mut TlsReader<'a>) -> Option<Self> {
        let start = reader.position();
        let encryption_key = reader.vector()?;
        let signature_key = reader.vector()?;

        if reader.u16()? != BASIC_CREDENTIAL {
            return None;
        }
        let identity = reader.vector()?;

        let _versions = reader.items(TlsReader::u16)?;
        let cipher_suites = reader.items(TlsReader::u16)?;
        let _extensions = reader.items(TlsReader::u16)?;
        let _proposals = reader.items(TlsReader::u16)?;
        let credentials = reader.items(TlsReader::u16)?;

        let lifetime = match reader.u8()? {
            LEAF_SOURCE_KEY_PACKAGE => Some((reader.u64()?, reader.u64()?)),
            LEAF_SOURCE_UPDATE => None,
            LEAF_SOURCE_COMMIT => {
                let _parent_hash = reader.vector()?;
                None
            }
            _ => return None,
        };
        let _extensions = reader.vector()?;
        let tbs = reader.since(start);
        let signature = reader.vector()?;

        Some(Self {
            encryption_key,
            signature_key,
            identity,
            cipher_suites,
            credentials,
            lifetime,
            tbs,
            signature,
        })
    }
}

pub struct KeyPackage<'a> {
    /// The whole encoded KeyPackage, as embedded in an Add proposal.
    pub raw: &'a [u8],
    pub leaf: LeafNode<'a>,
    cipher_suite: u16,
    init_key: &'a [u8],
    tbs: &'a [u8],
    signature: &'a [u8],
}

impl<'a> KeyPackage<'a> {
    /// A bare KeyPackage, as DAVE clients send it in op 26.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut reader = TlsReader::new(data);
        let key_package = Self::read(&mut reader)?;
        reader.is_empty().then_some(key_package)
    }

    fn read(reader: &mut TlsReader<'a>) -> Option<Self> {
        let start = reader.position();
        if reader.u16()? != MLS10 {
            return None;
        }
        let cipher_suite = reader.u16()?;
        let init_key = reader.vector()?;
        let leaf = LeafNode::parse(reader)?;
        let _extensions = reader.vector()?;
        let tbs = reader.since(start);
        let signature = reader.vector()?;

        Some(Self {
            raw: reader.since(start),
            leaf,
            cipher_suite,
            init_key,
            tbs,
            signature,
        })
    }

    /// The checks of the DAVE whitepaper ("Validation") and RFC 9420
    /// section 10.1 that need no group state.
    pub fn validate(&self, user_id: u64) -> Result<(), Invalid> {
        let leaf = &self.leaf;
        if self.cipher_suite != CIPHER_SUITE {
            return Err(Invalid("cipher suite"));
        }
        if leaf.identity != user_id.to_be_bytes() {
            return Err(Invalid("identity is not the session's user"));
        }
        if leaf.lifetime != Some((0, u64::MAX)) {
            return Err(Invalid("lifetime"));
        }
        if !leaf.cipher_suites.contains(&CIPHER_SUITE)
            || !leaf.credentials.contains(&BASIC_CREDENTIAL)
        {
            return Err(Invalid("capabilities"));
        }
        if self.init_key == leaf.encryption_key {
            return Err(Invalid("init key equals encryption key"));
        }
        if !verify_with_label(leaf.signature_key, "LeafNodeTBS", leaf.tbs, leaf.signature) {
            return Err(Invalid("leaf node signature"));
        }
        if !verify_with_label(
            leaf.signature_key,
            "KeyPackageTBS",
            self.tbs,
            self.signature,
        ) {
            return Err(Invalid("key package signature"));
        }
        Ok(())
    }

    pub fn reference(&self) -> Ref {
        ref_hash("MLS 1.0 KeyPackage Reference", self.raw)
    }
}

/// A commit from op 28, checked only as far as a server can without group
/// secrets.
pub struct Commit<'a> {
    /// The whole MLSMessage, forwarded unchanged in op 29.
    pub raw: &'a [u8],
    pub group_id: &'a [u8],
    pub epoch: u64,
    pub sender_leaf: u32,
    pub proposal_refs: Vec<&'a [u8]>,
    /// The committer's new leaf, if the commit has an UpdatePath.
    pub path_leaf: Option<LeafNode<'a>>,
}

impl<'a> Commit<'a> {
    fn read(reader: &mut TlsReader<'a>) -> Option<Self> {
        let start = reader.position();
        if reader.u16()? != MLS10 || reader.u16()? != WIRE_FORMAT_PUBLIC {
            return None;
        }

        let group_id = reader.vector()?;
        let epoch = reader.u64()?;
        if reader.u8()? != SENDER_MEMBER {
            return None;
        }
        let sender_leaf = reader.u32()?;
        let _authenticated_data = reader.vector()?;
        if reader.u8()? != CONTENT_COMMIT {
            return None;
        }

        // DAVE clients only commit proposals by reference.
        let proposal_refs = reader.items(|item| {
            if item.u8()? != PROPOSAL_OR_REF_REFERENCE {
                return None;
            }
            item.vector()
        })?;
        let path_leaf = match reader.u8()? {
            0 => None,
            1 => {
                let leaf = LeafNode::parse(reader)?;
                let _nodes = reader.vector()?;
                Some(leaf)
            }
            _ => return None,
        };

        let _signature = reader.vector()?;
        let _confirmation_tag = reader.vector()?;
        let _membership_tag = reader.vector()?;

        Some(Self {
            raw: reader.since(start),
            group_id,
            epoch,
            sender_leaf,
            proposal_refs,
            path_leaf,
        })
    }
}

pub struct Welcome<'a> {
    cipher_suite: u16,
    /// `(KeyPackageRef of the new member, encoded EncryptedGroupSecrets)`.
    secrets: Vec<(&'a [u8], &'a [u8])>,
    encrypted_group_info: &'a [u8],
}

impl<'a> Welcome<'a> {
    fn read(reader: &mut TlsReader<'a>) -> Option<Self> {
        let cipher_suite = reader.u16()?;
        let secrets = reader.items(|item| {
            let start = item.position();
            let new_member = item.vector()?;
            let _kem_output = item.vector()?;
            let _ciphertext = item.vector()?;
            Some((new_member, item.since(start)))
        })?;
        let encrypted_group_info = reader.vector()?;

        Some(Self {
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
    }

    pub fn new_members(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.secrets.iter().map(|&(new_member, _)| new_member)
    }

    /// The Welcome with only `new_member`'s secrets, for op 30.
    pub fn for_member(&self, new_member: &[u8]) -> Option<Vec<u8>> {
        let &(_, entry) = self
            .secrets
            .iter()
            .find(|&&(member, _)| member == new_member)?;

        let mut writer = TlsWriter::default();
        writer
            .u16(self.cipher_suite)
            .vector(entry)
            .vector(self.encrypted_group_info);
        Some(writer.into_bytes())
    }
}

/// Op 28: a commit MLSMessage, then a bare Welcome if any bytes remain.
pub fn parse_commit_welcome(data: &[u8]) -> Option<(Commit<'_>, Option<Welcome<'_>>)> {
    let mut reader = TlsReader::new(data);
    let commit = Commit::read(&mut reader)?;
    if reader.is_empty() {
        return Some((commit, None));
    }

    let welcome = Welcome::read(&mut reader)?;
    if !reader.is_empty() || welcome.cipher_suite != CIPHER_SUITE {
        return None;
    }
    Some((commit, Some(welcome)))
}

/// A signed proposal from the external sender, ready for op 27.
pub struct Proposal {
    pub message: Vec<u8>,
    pub reference: Ref,
}

/// The voice gateway as the group's only external sender.
pub struct ExternalSender {
    key: SigningKey,
    /// The encoded `ExternalSender` struct, sent as op 25.
    pub encoded: Vec<u8>,
}

impl ExternalSender {
    pub fn generate() -> Self {
        let key = loop {
            let mut secret = [0; 32];
            getrandom::fill(&mut secret).expect("system RNG");
            if let Ok(key) = SigningKey::from_slice(&secret) {
                break key;
            }
        };

        let mut writer = TlsWriter::default();
        writer
            .vector(&key.verifying_key().to_sec1_bytes())
            .u16(BASIC_CREDENTIAL)
            .vector(&[0]);
        Self {
            key,
            encoded: writer.into_bytes(),
        }
    }

    pub fn add(&self, group_id: &[u8], epoch: u64, key_package: &KeyPackage) -> Proposal {
        let mut body = TlsWriter::default();
        body.u16(PROPOSAL_ADD).bytes(key_package.raw);
        self.propose(group_id, epoch, &body.into_bytes())
    }

    pub fn remove(&self, group_id: &[u8], epoch: u64, leaf: u32) -> Proposal {
        let mut body = TlsWriter::default();
        body.u16(PROPOSAL_REMOVE).u32(leaf);
        self.propose(group_id, epoch, &body.into_bytes())
    }

    fn propose(&self, group_id: &[u8], epoch: u64, proposal: &[u8]) -> Proposal {
        let mut content = TlsWriter::default();
        content
            .vector(group_id)
            .u64(epoch)
            .u8(SENDER_EXTERNAL)
            .u32(0)
            .vector(&[])
            .u8(CONTENT_PROPOSAL)
            .bytes(proposal);
        let content = content.into_bytes();

        let mut tbs = TlsWriter::default();
        tbs.u16(MLS10).u16(WIRE_FORMAT_PUBLIC).bytes(&content);
        let signature = sign_with_label(&self.key, "FramedContentTBS", &tbs.into_bytes());

        let mut authenticated = TlsWriter::default();
        authenticated
            .u16(WIRE_FORMAT_PUBLIC)
            .bytes(&content)
            .vector(&signature);
        let authenticated = authenticated.into_bytes();

        let mut message = TlsWriter::default();
        message.u16(MLS10).bytes(&authenticated);
        Proposal {
            message: message.into_bytes(),
            reference: ref_hash("MLS 1.0 Proposal Reference", &authenticated),
        }
    }
}

/// Op 27 `append`: `uint8 0`, then `MLSMessage proposal_messages<V>`.
pub fn proposals_append<'a>(messages: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let joined: Vec<u8> = messages.into_iter().flatten().copied().collect();
    let mut writer = TlsWriter::default();
    writer.u8(0).vector(&joined);
    writer.into_bytes()
}

/// Op 27 `revoke`: `uint8 1`, then `ProposalRef proposal_refs<V>`.
pub fn proposals_revoke<'a>(refs: impl IntoIterator<Item = &'a Ref>) -> Vec<u8> {
    let mut joined = TlsWriter::default();
    for reference in refs {
        joined.vector(reference);
    }
    let mut writer = TlsWriter::default();
    writer.u8(1).vector(&joined.into_bytes());
    writer.into_bytes()
}

/// `RefHash(label, value)` (RFC 9420 section 5.2).
fn ref_hash(label: &str, value: &[u8]) -> Ref {
    let mut input = TlsWriter::default();
    input.vector(label.as_bytes()).vector(value);
    Sha256::digest(input.into_bytes()).into()
}

/// `SignContent` (RFC 9420 section 5.1.2).
fn sign_content(label: &str, content: &[u8]) -> Vec<u8> {
    let mut writer = TlsWriter::default();
    writer
        .vector(format!("MLS 1.0 {label}").as_bytes())
        .vector(content);
    writer.into_bytes()
}

fn sign_with_label(key: &SigningKey, label: &str, content: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(&sign_content(label, content));
    signature.to_der().as_bytes().to_vec()
}

fn verify_with_label(key: &[u8], label: &str, content: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(key),
        DerSignature::from_bytes(signature),
    ) else {
        return false;
    };
    key.verify(&sign_content(label, content), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(Reader::new(&body[1..]).vector().unwrap(), remove.message);

        let body = proposals_revoke([&remove.reference]);
        let mut reader = TlsReader::new(&body[1..]);
        let refs = reader.items(TlsReader::vector).unwrap();
        assert_eq!(body[0], 1);
        assert_eq!(refs, [&remove.reference[..]]);
    }
}
