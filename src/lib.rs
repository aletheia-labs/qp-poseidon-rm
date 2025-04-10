#![cfg_attr(not(feature = "std"), no_std)]

use scale_info::TypeInfo;
use sp_runtime::traits::Hash;
use sp_core::Hasher;
use sp_core::H256;
use sp_runtime::{RuntimeDebug, Vec};
use sp_storage::StateVersion;
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};
use core::hash::Hasher as StdHasher;
use codec::{Encode};
use log;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericHashOut, Hasher as PlonkyHasher};
#[cfg(feature = "serde")]
use sp_runtime::{Deserialize, Serialize};

#[derive(Default)]
pub struct PoseidonStdHasher(Vec<u8>);

impl StdHasher for PoseidonStdHasher {
    fn finish(&self) -> u64 {
        let hash = poseidon_hash(self.0.as_slice()).0;
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes)
    }
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoseidonHasher;

impl Hasher for PoseidonHasher {
    type Out = H256;
    type StdHasher = PoseidonStdHasher;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> H256 {
        poseidon_hash(x)
    }
}


fn poseidon_hash(x: &[u8]) -> H256 {
    // We don't want to exceed the scalar field modulus, so we only take 7 bytes at a time
    const BYTES_PER_ELEMENT: usize = 8;
    // const BYTES_PER_ELEMENT: usize = 7;

    let mut field_elements: Vec<GoldilocksField> = Vec::new();
    for chunk in x.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element
        let value = u64::from_le_bytes(bytes);
        let field_element = GoldilocksField::from_noncanonical_u64(value);
        // let field_element = GoldilocksField::from_canonical_u64(value);
        field_elements.push(field_element);
    }

    log::debug!("field_elements: {:?}", field_elements);

    if x.len() == 0 {
        log::info!("PoseidonHasher::hash EMPTY INPUT");
        field_elements.push(GoldilocksField::ZERO);
    }

    let hash = PoseidonHash::hash_no_pad(&field_elements);
    log::debug!("poseidonHasher::hash : {:?}", hash);

    let h256 = H256::from_slice(&*hash.to_bytes());
    log::debug!("hash output: {:?}", h256);

    h256
}

impl Hash for PoseidonHasher {
    type Output = H256;

    fn hash(s: &[u8]) -> Self::Output {
        poseidon_hash(s)
    }

    /// Produce the hash of some codec-encodable value.
    fn hash_of<S: Encode>(s: &S) -> Self::Output {
        Encode::using_encoded(s, <Self as Hasher>::hash)
    }

    fn ordered_trie_root(input: Vec<Vec<u8>>, state_version: StateVersion) -> Self::Output {
        log::info!("PoseidonHasher::ordered_trie_root input={:?} version={:?}", input, state_version);
        let res = match state_version {
            StateVersion::V0 => LayoutV0::<PoseidonHasher>::ordered_trie_root(input),
            StateVersion::V1 => LayoutV1::<PoseidonHasher>::ordered_trie_root(input),
        };
        log::info!("PoseidonHasher::ordered_trie_root res={:?}", res);
        res
    }

    fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
        log::info!("PoseidonHasher::trie_root input={:?} version={:?}", input, version);
        let res = match version {
            StateVersion::V0 => LayoutV0::<PoseidonHasher>::trie_root(input),
            StateVersion::V1 => LayoutV1::<PoseidonHasher>::trie_root(input),
        };
        log::info!("PoseidonHasher::trie_root res={:?}", res);
        res
    }

}
#[cfg(test)]
mod tests {
    use plonky2::field::types::Field64;
    use super::*;
    use hex;

    #[test]
    fn test_empty_input() {
        let result = <PoseidonHasher as Hasher>::hash(&[]);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_single_byte() {
        let input = vec![42u8];
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_exactly_32_bytes() {
        let input = [1u8; 32];
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_multiple_chunks() {
        let input = [2u8; 64]; // Two chunks
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_partial_chunk() {
        let input = [3u8; 40]; // One full chunk plus 8 bytes
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    // #[test]
    // fn test_known_value() {
    //     // Replace these with actual known input/output pairs for your implementation
    //     let input = decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    //     let result = <PoseidonHasher as Hasher>::hash(&input);
    //     assert_eq!(result.0.len(), 32);
    // }

    #[test]
    fn test_consistency() {
        let input = [4u8; 50];
        let iterations = 100;
        let current_hash = <PoseidonHasher as Hasher>::hash(&input); // Compute the first hash

        for _ in 0..iterations {
            let hash1 = <PoseidonHasher as Hasher>::hash((&current_hash).as_ref());
            let current_hash = <PoseidonHasher as Hasher>::hash((&current_hash).as_ref());
            assert_eq!(hash1, current_hash, "Hash function should be deterministic");
        }
    }

    #[test]
    fn test_different_inputs() {
        let input1 = [5u8; 32];
        let input2 = [6u8; 32];
        let hash1 = <PoseidonHasher as Hasher>::hash(&input1);
        let hash2 = <PoseidonHasher as Hasher>::hash(&input2);
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_poseidon_hash_input_sizes() {

        // Test inputs from 1 to 128 bytes
        for size in 1..=128 {
            // Create a predictable input: repeating byte value based on size
            let input: Vec<u8> = (0..size).map(|i| (i*i % 256) as u8).collect();
            let hash = <PoseidonHasher as Hasher>::hash(&input);
            println!("Size {}: {:?}", size, hash);

            // Assertions
            assert_eq!(
                hash.as_bytes().len(),
                32,
                "Input size {} should produce 32-byte H256",
                size
            );
        }
    }

    #[test]
    fn test_big_preimage() {
        for overflow in 1..=200 {
            let preimage = GoldilocksField::ORDER + overflow;
            let hash = <PoseidonHasher as Hasher>::hash(preimage.to_le_bytes().as_ref());
        }
    }

    #[test]
    fn test_circuit_preimage() {
        let preimage = hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
        let hash = <PoseidonHasher as Hasher>::hash(&*preimage.unwrap());
        let hash2 = <PoseidonHasher as Hasher>::hash(hash.as_bytes());
    }

    #[test]
    fn test_random_inputs() {
        let hex_strings = [
            "a3f8",
            "1b7e9d",
            "4c2a6f81",
            "e5d30b9a",
            "1a4f7c2e9b0d8356",
            "3e8d2a7f5c1b09e4d6f7a2c8",
            "7b3e9a1f4c8d2e6b0a5f9d3c",
            "1a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d8356",
            "e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81",
        ];

        for hex_string in hex_strings.iter() {
            let preimage = hex::decode(hex_string).unwrap();
            println!("input: {}", hex_string);
            let hash = <PoseidonHasher as Hasher>::hash(&preimage);
            let hash2 = <PoseidonHasher as Hasher>::hash(&hash.as_bytes());
        }
    }

    // #[test]
    // fn test_empty_blake2() {
    //     let result = <BlakeTwo256 as Hasher>::hash(&[]);
    //     println!("hash output: {:?}", result);
    //     assert_eq!(result.0.len(), 32);
    // }
}