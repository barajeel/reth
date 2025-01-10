use crate::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use alloy_primitives::{keccak256, map::HashMap, Address, B256};
use reth_db_api::transaction::DbTx;
use reth_execution_errors::StateProofError;
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory,
    proof::{Proof, StorageProof},
    trie_cursor::InMemoryTrieCursorFactory,
    AccountProof, HashedPostStateSorted, HashedStorage, MultiProof, MultiProofTargets,
    StorageMultiProof, TrieInput,
};

extern crate alloc;
use alloc::sync::Arc;

/// Extends [`Proof`] with operations specific for working with a database transaction.
pub trait DatabaseProof<TX> {
    /// Create a new [Proof] from database transaction.
    fn from_tx(tx: Arc<TX>) -> Self;

    /// Generates the state proof for target account based on [`TrieInput`].
    fn overlay_account_proof(
        tx: Arc<TX>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError>;

    /// Generates the state [`MultiProof`] for target hashed account and storage keys.
    fn overlay_multiproof(
        tx: Arc<TX>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError>;
}

impl<TX: DbTx> DatabaseProof<TX>
    for Proof<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>
{
    /// Create a new [Proof] instance from database transaction.
    fn from_tx(tx: Arc<TX>) -> Self {
        Self::new(DatabaseTrieCursorFactory::new(tx.clone()), DatabaseHashedCursorFactory::new(tx))
    }

    fn overlay_account_proof(
        tx: Arc<TX>,
        input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();
        Self::from_tx(tx.clone())
            .with_trie_cursor_factory(InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(tx.clone()),
                &nodes_sorted,
            ))
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_sets_mut(input.prefix_sets)
            .account_proof(address, slots)
    }

    fn overlay_multiproof(
        tx: Arc<TX>,
        input: TrieInput,
        targets: MultiProofTargets,
    ) -> Result<MultiProof, StateProofError> {
        let nodes_sorted = input.nodes.into_sorted();
        let state_sorted = input.state.into_sorted();
        Self::from_tx(tx.clone())
            .with_trie_cursor_factory(InMemoryTrieCursorFactory::new(
                DatabaseTrieCursorFactory::new(tx.clone()),
                &nodes_sorted,
            ))
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_sets_mut(input.prefix_sets)
            .multiproof(targets)
    }
}

/// Extends [`StorageProof`] with operations specific for working with a database transaction.
pub trait DatabaseStorageProof<TX> {
    /// Create a new [`StorageProof`] from database transaction and account address.
    fn from_tx(tx: Arc<TX>, address: Address) -> Self;

    /// Generates the storage proof for target slot based on [`TrieInput`].
    fn overlay_storage_proof(
        tx: Arc<TX>,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError>;

    /// Generates the storage multiproof for target slots based on [`TrieInput`].
    fn overlay_storage_multiproof(
        tx: Arc<TX>,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError>;
}

impl<TX: DbTx> DatabaseStorageProof<TX>
    for StorageProof<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>
{
    fn from_tx(tx: Arc<TX>, address: Address) -> Self {
        Self::new(
            DatabaseTrieCursorFactory::new(tx.clone()),
            DatabaseHashedCursorFactory::new(tx),
            address,
        )
    }

    fn overlay_storage_proof(
        tx: Arc<TX>,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> Result<reth_trie::StorageProof, StateProofError> {
        let hashed_address = keccak256(address);
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_tx(tx.clone(), address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_proof(slot)
    }

    fn overlay_storage_multiproof(
        tx: Arc<TX>,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> Result<StorageMultiProof, StateProofError> {
        let hashed_address = keccak256(address);
        let targets = slots.iter().map(keccak256).collect();
        let prefix_set = storage.construct_prefix_set();
        let state_sorted = HashedPostStateSorted::new(
            Default::default(),
            HashMap::from_iter([(hashed_address, storage.into_sorted())]),
        );
        Self::from_tx(tx.clone(), address)
            .with_hashed_cursor_factory(HashedPostStateCursorFactory::new(
                DatabaseHashedCursorFactory::new(tx),
                &state_sorted,
            ))
            .with_prefix_set_mut(prefix_set)
            .storage_multiproof(targets)
    }
}
