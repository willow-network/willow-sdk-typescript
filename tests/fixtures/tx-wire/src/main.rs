//! Generates `tests/fixtures/tx-wire/wrappers.json`.
//!
//! The TypeScript SDK submits transactions as JSON to the API server's
//! `POST /tx/submit`, which deserializes them with `Json<Transaction>`
//! (serde_json, strict — no lenient hex->bytes coercion). The chain's tx
//! structs declare `signature: Vec<u8>` and digest fields like
//! `content_hash: [u8; 32]` without `serde_bytes`, so a hex string is
//! rejected with a 422 before the handler ever runs.
//!
//! This generator builds one transaction of each kind the SDK's
//! `createTransactionWrapper` emits, serializes it with the exact serde_json
//! the API server uses, and writes the result as a golden file. It also
//! round-trips every golden back through `serde_json::from_str::<Transaction>`
//! — the same call the extractor makes — so the fixture is provably the wire
//! shape the chain accepts. The TS test asserts its wrapper output equals
//! these goldens, so any future drift (a hex string, a camelCase key, a
//! renamed field) fails mechanically.
//!
//! Run with:
//!   cargo run --release --manifest-path tests/fixtures/tx-wire/Cargo.toml

use std::path::PathBuf;

use serde_json::{json, Value};
use willow_types::consensus::transactions::{
    DeleteFileManifestTx, GrantSubgroveKeyTx, RevokeSubgroveKeyTx, RotateSubgroveKeyTx,
    StoreFileManifestTx, Transaction, UnregisterStorageNodeTx,
};
use willow_types::storage::EncryptedKeyGrant;

/// Fixed inputs shared with the TS test so the goldens are reproducible.
const SUBGROVE_ID: &str = "private-data";
const OWNER_DID: &str = "did:willow:owner";
const SENDER_DID: &str = "did:willow:owner";
const KEY_ID: &str = "did:willow:owner#key-1";
const FILE_KEY: &str = "file-1";
const NODE_DID: &str = "did:willow:storage1";
const NONCE: u64 = 7;

/// 64-byte ed25519 signature: bytes 0..64.
fn signature() -> Vec<u8> {
    (0u8..64).collect()
}

/// 32-byte digest filled with a fixed pattern.
fn digest(seed: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    d
}

fn sample_grant() -> EncryptedKeyGrant {
    EncryptedKeyGrant {
        grantee_did: "did:willow:reader".to_string(),
        key_epoch: 1,
        grantee_public_key_id: "did:willow:reader#key-1".to_string(),
        ephemeral_public_key: vec![1, 2, 3],
        encrypted_key: vec![4, 5, 6],
        granted_by: OWNER_DID.to_string(),
        granted_at: 1_700_000_000,
    }
}

/// Build every transaction whose wire shape the SDK's single encoder owns.
fn cases() -> Vec<(&'static str, Transaction)> {
    vec![
        (
            "StoreFileManifest",
            Transaction::StoreFileManifest(StoreFileManifestTx {
                subgrove_id: SUBGROVE_ID.to_string(),
                file_key: FILE_KEY.to_string(),
                filename: "doc.json".to_string(),
                content_type: "application/json".to_string(),
                total_size: 17,
                content_hash: digest(0x11),
                chunk_count: 1,
                chunk_size: 262_144,
                chunk_merkle_root: digest(0x22),
                owner_did: OWNER_DID.to_string(),
                encryption: None,
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
        (
            "DeleteFileManifest",
            Transaction::DeleteFileManifest(DeleteFileManifestTx {
                subgrove_id: SUBGROVE_ID.to_string(),
                file_key: FILE_KEY.to_string(),
                owner_did: OWNER_DID.to_string(),
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
        (
            "UnregisterStorageNode",
            Transaction::UnregisterStorageNode(UnregisterStorageNodeTx {
                node_did: NODE_DID.to_string(),
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
        (
            "GrantSubgroveKey",
            Transaction::GrantSubgroveKey(GrantSubgroveKeyTx {
                subgrove_id: SUBGROVE_ID.to_string(),
                encrypted_key_grant: sample_grant(),
                sender_did: SENDER_DID.to_string(),
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
        (
            "RevokeSubgroveKey",
            Transaction::RevokeSubgroveKey(RevokeSubgroveKeyTx {
                subgrove_id: SUBGROVE_ID.to_string(),
                revokee_did: "did:willow:reader".to_string(),
                sender_did: SENDER_DID.to_string(),
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
        (
            "RotateSubgroveKey",
            Transaction::RotateSubgroveKey(RotateSubgroveKeyTx {
                subgrove_id: SUBGROVE_ID.to_string(),
                new_epoch: 2,
                new_grants: vec![sample_grant()],
                sender_did: SENDER_DID.to_string(),
                signature: signature(),
                public_key_id: KEY_ID.to_string(),
                nonce: NONCE,
            }),
        ),
    ]
}

fn main() {
    let mut wrappers = serde_json::Map::new();

    for (kind, tx) in cases() {
        // Serialize exactly as the API server would round-trip it.
        let wire = serde_json::to_value(&tx).expect("serialize Transaction");

        // Prove the chain's deserializer accepts this shape: this is the same
        // `serde_json::from_str::<Transaction>` call the `Json<Transaction>`
        // extractor makes. A hex string or a camelCase key would error here.
        let json = serde_json::to_string(&wire).unwrap();
        let _back: Transaction = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("{kind} failed to round-trip through Transaction: {e}"));

        // Sanity: the variant key matches what the SDK wraps with.
        let obj = wire.as_object().expect("Transaction serializes as a map");
        assert_eq!(obj.len(), 1, "{kind}: externally-tagged enum has one key");
        assert!(obj.contains_key(kind), "{kind}: variant key mismatch");

        wrappers.insert(kind.to_string(), wire);
    }

    let out = json!({
        "description": "Golden wire JSON for each tx kind the TS SDK's \
            createTransactionWrapper emits, produced by serializing the real \
            willow_types::Transaction and verified to round-trip through the \
            chain's serde_json deserializer.",
        "generator": "tests/fixtures/tx-wire/src/main.rs",
        "willow_types_rev": "ed8ccff09f0b6be0fd91c253ce3b5c42e0e2b1b1",
        "wrappers": Value::Object(wrappers),
    });

    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wrappers.json");
    std::fs::write(&dest, format!("{}\n", serde_json::to_string_pretty(&out).unwrap()))
        .expect("write wrappers.json");
    eprintln!("wrote {}", dest.display());
}
