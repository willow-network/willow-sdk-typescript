//! Generates `tests/fixtures/grovedb/partial-proof-live.json`.
//!
//! Mirrors the canonical fixture generator in the Willow chain repo
//! (`crates/storage/tests/generate_ts_fixtures.rs`): it builds a real GroveDB,
//! produces a proof with `prove_query`, round-trip verifies it with the Rust
//! verifier, and dumps the bytes as JSON for the TypeScript test suite.
//!
//! This fixture regression-tests the AVL-balance false negative: a single-key
//! query into a tree with a few hundred keys yields a *partial* reconstruction
//! where only the queried path is expanded and sibling subtrees collapse to
//! height-0 hash nodes — legitimately unbalanced, so any verifier that asserts
//! AVL balance on it rejects a valid proof.
//!
//! Run with:
//!   cargo run --release --manifest-path tests/fixtures/grovedb/generator/Cargo.toml

use std::path::PathBuf;

use grovedb::{Element, GroveDb, PathQuery, Query};
use grovedb_version::version::GroveVersion;
use serde::Serialize;
use tempfile::TempDir;

const SUBGROVE_ID: &str = "demo-vault-events";
const EVENT_TREE: &str = "Deposit";
const EVENT_COUNT: u64 = 300;
const QUERIED_INDEX: u64 = 137;

#[derive(Serialize)]
struct PartialProofFixture {
    description: String,
    generator: &'static str,
    #[serde(rename = "proofHex")]
    proof_hex: String,
    #[serde(rename = "stateRootHex")]
    state_root_hex: String,
    key: String,
    path: String,
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

// Deterministic keys shaped like indexed-event ids: "0x<64 hex>-<ordinal>".
fn event_key(i: u64) -> String {
    let mut s = i;
    let h: String = (0..4).map(|_| format!("{:016x}", splitmix64(&mut s))).collect();
    format!("0x{}-{}", h, i)
}

// Small JSON document per event so the document-binding tests in the TS suite
// can parse the proven Item value.
fn event_value(i: u64) -> Vec<u8> {
    let mut s = i ^ 0xABCD_EF01_2345_6789;
    let doc = serde_json::json!({
        "event": "Deposit",
        "sender": format!("0x{:040x}", splitmix64(&mut s) as u128),
        "assets": format!("{}", 1_000_000_000_000_000u64 + 13 * i),
        "shares": format!("{}", 990_000_000_000_000u64 + 11 * i),
        "block_number": 18_000_000 + i,
        "log_index": i % 7,
    });
    serde_json::to_vec(&doc).unwrap()
}

fn output_path() -> PathBuf {
    // generator/ → tests/fixtures/grovedb/partial-proof-live.json
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("partial-proof-live.json")
}

fn main() {
    let temp_dir = TempDir::new().unwrap();
    let db = GroveDb::open(temp_dir.path()).unwrap();
    let version = GroveVersion::latest();
    let empty: &[&[u8]] = &[];

    // Mirror the chain layout: root → subgroves → <id> → indexed → <entity> → events.
    // Sibling trees at every layer keep each merk proof non-trivial.
    for top in [b"subgroves" as &[u8], b"balances", b"dids"] {
        db.insert(empty, top, Element::empty_tree(), None, None, version)
            .unwrap()
            .unwrap();
    }
    for sub in [SUBGROVE_ID.as_bytes(), b"demo-amm-pools", b"demo-token-transfers"] {
        db.insert(
            &[b"subgroves" as &[u8]],
            sub,
            Element::empty_tree(),
            None,
            None,
            version,
        )
        .unwrap()
        .unwrap();
    }
    db.insert(
        &[b"subgroves" as &[u8], SUBGROVE_ID.as_bytes()],
        b"indexed",
        Element::empty_tree(),
        None,
        None,
        version,
    )
    .unwrap()
    .unwrap();
    db.insert(
        &[b"subgroves" as &[u8], SUBGROVE_ID.as_bytes()],
        b"config",
        Element::new_item(b"{\"start_block\":18000000}".to_vec()),
        None,
        None,
        version,
    )
    .unwrap()
    .unwrap();
    for entity in [EVENT_TREE.as_bytes(), b"Transfer", b"Withdraw"] {
        db.insert(
            &[
                b"subgroves" as &[u8],
                SUBGROVE_ID.as_bytes(),
                b"indexed",
            ],
            entity,
            Element::empty_tree(),
            None,
            None,
            version,
        )
        .unwrap()
        .unwrap();
    }

    let events_path: &[&[u8]] = &[
        b"subgroves",
        SUBGROVE_ID.as_bytes(),
        b"indexed",
        EVENT_TREE.as_bytes(),
    ];
    for i in 0..EVENT_COUNT {
        db.insert(
            events_path,
            event_key(i).as_bytes(),
            Element::new_item(event_value(i)),
            None,
            None,
            version,
        )
        .unwrap()
        .unwrap();
    }

    let root_hash: [u8; 32] = db.root_hash(None, version).unwrap().unwrap();

    let queried_key = event_key(QUERIED_INDEX);
    let path_bytes: Vec<Vec<u8>> = vec![
        b"subgroves".to_vec(),
        SUBGROVE_ID.as_bytes().to_vec(),
        b"indexed".to_vec(),
        EVENT_TREE.as_bytes().to_vec(),
    ];
    let query = Query::new_single_key(queried_key.as_bytes().to_vec());
    let path_query = PathQuery::new_unsized(path_bytes, query);
    let proof: Vec<u8> = db.prove_query(&path_query, None, version).unwrap().unwrap();

    // Sanity check: round-trip verify with the Rust verifier before writing.
    let (computed_root, items) =
        GroveDb::verify_query(&proof, &path_query, version).expect("round-trip verify");
    assert_eq!(
        computed_root, root_hash,
        "rust round-trip: computed != stored root",
    );
    assert_eq!(items.len(), 1, "expected exactly one proven item");

    let fixture = PartialProofFixture {
        description: format!(
            "Single-key proof for one of {} events in subgroves/{}/indexed/{}; \
             the partial reconstruction is unbalanced (collapsed sibling subtrees), \
             regression for the AVL-balance false negative",
            EVENT_COUNT, SUBGROVE_ID, EVENT_TREE,
        ),
        generator: "tests/fixtures/grovedb/generator",
        proof_hex: hex::encode(&proof),
        state_root_hex: hex::encode(root_hash),
        key: queried_key,
        path: format!("subgroves/{}/indexed/{}", SUBGROVE_ID, EVENT_TREE),
    };

    let out = output_path();
    std::fs::write(&out, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
    eprintln!("wrote fixture: {}", out.display());
}
