use crate::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use alloy_primitives::{map::B256HashMap, Bytes};
use reth_db_api::transaction::DbTx;
use reth_execution_errors::TrieWitnessError;
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory, trie_cursor::InMemoryTrieCursorFactory,
    witness::TrieWitness, HashedPostState, TrieInput,
};

extern crate alloc;
use alloc::sync::Arc;

/// Extends [`TrieWitness`] with operations specific for working with a database transaction.
pub trait DatabaseTrieWitness<TX> {
    /// Create a new [`TrieWitness`] from database transaction.
    fn from_tx(tx: Arc<TX>) -> Self;

    /// Generates trie witness for target state based on [`TrieInput`].
    fn overlay_witness(
        tx: Arc<TX>,
        input: TrieInput,
        target: HashedPostState,
    ) -> Result<B256HashMap<Bytes>, TrieWitnessError>;
}

impl<TX: DbTx> DatabaseTrieWitness<TX>
    for TrieWitness<DatabaseTrieCursorFactory<TX>, DatabaseHashedCursorFactory<TX>>
{
    fn from_tx(tx: Arc<TX>) -> Self {
        Self::new(DatabaseTrieCursorFactory::new(tx.clone()), DatabaseHashedCursorFactory::new(tx))
    }

    fn overlay_witness(
        tx: Arc<TX>,
        input: TrieInput,
        target: HashedPostState,
    ) -> Result<B256HashMap<Bytes>, TrieWitnessError> {
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
            .compute(target)
    }
}
