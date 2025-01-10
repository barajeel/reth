use crate::{
    DatabaseHashedCursorFactory, DatabaseProof, DatabaseStateRoot, DatabaseStorageRoot,
    DatabaseTrieCursorFactory, DatabaseTrieWitness,
};
use reth_db::transaction::DbTx;
use reth_trie::{
    proof::Proof, witness::TrieWitness, KeccakKeyHasher, KeyHasher, StateRoot, StorageRoot,
};

/// The `StateCommitment` trait provides associated types for state commitment operations.
pub trait StateCommitment: std::fmt::Debug + Send + Sync + Unpin + 'static {
    /// The state root type.
    type StateRoot<TX: DbTx>: DatabaseStateRoot<TX>;
    /// The storage root type.
    type StorageRoot<TX: DbTx>: DatabaseStorageRoot<TX>;
    /// The state proof type.
    type StateProof<TX: DbTx>: DatabaseProof<TX>;
    /// The state witness type.
    type StateWitness<TX: DbTx>: DatabaseTrieWitness<TX>;
    /// The key hasher type.
    type KeyHasher: KeyHasher;
}

/// The state commitment type for Ethereum's Merkle Patricia Trie.
#[derive(Debug)]
#[non_exhaustive]
pub struct MerklePatriciaTrie;

impl StateCommitment for MerklePatriciaTrie {
    type StateRoot<TX: DbTx> =
        StateRoot<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>;
    type StorageRoot<TX: DbTx> =
        StorageRoot<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>;
    type StateProof<TX: DbTx> =
        Proof<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>;
    type StateWitness<TX: DbTx> =
        TrieWitness<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>;
    type KeyHasher = KeccakKeyHasher;
}
