//! This crate contains the protocol for computing TLS 1.2 SHA-256 HMAC PRF.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod hmac;
#[cfg(test)]
mod test_utils;

mod config;
pub use config::Mode;

mod error;
pub use error::PrfError;

mod prf;
pub use prf::MpcPrf;

use mpz_vm_core::memory::{binary::U8, Array};

/// PRF output.
#[derive(Debug, Clone, Copy)]
pub struct PrfOutput {
    /// TLS session keys.
    pub keys: SessionKeys,
    /// Client finished verify data.
    pub cf_vd: Array<U8, 12>,
    /// Server finished verify data.
    pub sf_vd: Array<U8, 12>,
}

/// Session keys computed by the PRF.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 4>,
    /// Server IV.
    pub server_iv: Array<U8, 4>,
}

fn sha256(mut state: [u32; 8], pos: usize, msg: &[u8]) -> [u32; 8] {
    use sha2::{
        compress256,
        digest::{
            block_buffer::{BlockBuffer, Eager},
            generic_array::typenum::U64,
        },
    };

    let mut buffer = BlockBuffer::<U64, Eager>::default();
    buffer.digest_blocks(msg, |b| compress256(&mut state, b));
    buffer.digest_pad(0x80, &(((msg.len() + pos) * 8) as u64).to_be_bytes(), |b| {
        compress256(&mut state, &[*b])
    });
    state
}

fn state_to_bytes(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (k, byte_chunk) in input.iter().enumerate() {
        let byte_chunk = byte_chunk.to_be_bytes();
        output[4 * k..4 * (k + 1)].copy_from_slice(&byte_chunk);
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::{mock_vm, prf_cf_vd, prf_keys, prf_ms, prf_sf_vd},
        Mode, MpcPrf, SessionKeys,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[tokio::test]
    async fn test_prf_reduced() {
        let mode = Mode::Reduced;
        test_prf(mode).await;
    }

    #[tokio::test]
    async fn test_prf_normal() {
        let mode = Mode::Normal;
        test_prf(mode).await;
    }

    async fn test_prf(mode: Mode) {
        let mut rng = StdRng::seed_from_u64(1);
        // Test input
        let pms: [u8; 32] = rng.random();
        let client_random: [u8; 32] = rng.random();
        let server_random: [u8; 32] = rng.random();

        let cf_hs_hash: [u8; 32] = rng.random();
        let sf_hs_hash: [u8; 32] = rng.random();

        // Expected output
        let ms_expected = prf_ms(pms, client_random, server_random);

        let [cwk_expected, swk_expected, civ_expected, siv_expected] =
            prf_keys(ms_expected, client_random, server_random);

        let cwk_expected: [u8; 16] = cwk_expected.try_into().unwrap();
        let swk_expected: [u8; 16] = swk_expected.try_into().unwrap();
        let civ_expected: [u8; 4] = civ_expected.try_into().unwrap();
        let siv_expected: [u8; 4] = siv_expected.try_into().unwrap();

        let cf_vd_expected = prf_cf_vd(ms_expected, cf_hs_hash);
        let sf_vd_expected = prf_sf_vd(ms_expected, sf_hs_hash);

        let cf_vd_expected: [u8; 12] = cf_vd_expected.try_into().unwrap();
        let sf_vd_expected: [u8; 12] = sf_vd_expected.try_into().unwrap();

        // Set up vm and prf
        let (mut ctx_a, mut ctx_b) = test_st_context(128);
        let (mut leader, mut follower) = mock_vm();

        let leader_pms: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_pms).unwrap();
        leader.assign(leader_pms, pms).unwrap();
        leader.commit(leader_pms).unwrap();

        let follower_pms: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(follower_pms).unwrap();
        follower.assign(follower_pms, pms).unwrap();
        follower.commit(follower_pms).unwrap();

        let mut prf_leader = MpcPrf::new(mode);
        let mut prf_follower = MpcPrf::new(mode);

        let leader_prf_out = prf_leader.alloc(&mut leader, leader_pms).unwrap();
        let follower_prf_out = prf_follower.alloc(&mut follower, follower_pms).unwrap();

        // client_random and server_random
        prf_leader.set_client_random(client_random).unwrap();
        prf_follower.set_client_random(client_random).unwrap();

        prf_leader.set_server_random(server_random).unwrap();
        prf_follower.set_server_random(server_random).unwrap();

        let SessionKeys {
            client_write_key: cwk_leader,
            server_write_key: swk_leader,
            client_iv: civ_leader,
            server_iv: siv_leader,
        } = leader_prf_out.keys;

        let mut cwk_leader = leader.decode(cwk_leader).unwrap();
        let mut swk_leader = leader.decode(swk_leader).unwrap();
        let mut civ_leader = leader.decode(civ_leader).unwrap();
        let mut siv_leader = leader.decode(siv_leader).unwrap();

        let SessionKeys {
            client_write_key: cwk_follower,
            server_write_key: swk_follower,
            client_iv: civ_follower,
            server_iv: siv_follower,
        } = follower_prf_out.keys;

        let mut cwk_follower = follower.decode(cwk_follower).unwrap();
        let mut swk_follower = follower.decode(swk_follower).unwrap();
        let mut civ_follower = follower.decode(civ_follower).unwrap();
        let mut siv_follower = follower.decode(siv_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let cwk_leader = cwk_leader.try_recv().unwrap().unwrap();
        let swk_leader = swk_leader.try_recv().unwrap().unwrap();
        let civ_leader = civ_leader.try_recv().unwrap().unwrap();
        let siv_leader = siv_leader.try_recv().unwrap().unwrap();

        let cwk_follower = cwk_follower.try_recv().unwrap().unwrap();
        let swk_follower = swk_follower.try_recv().unwrap().unwrap();
        let civ_follower = civ_follower.try_recv().unwrap().unwrap();
        let siv_follower = siv_follower.try_recv().unwrap().unwrap();

        assert_eq!(cwk_leader, cwk_follower);
        assert_eq!(swk_leader, swk_follower);
        assert_eq!(civ_leader, civ_follower);
        assert_eq!(siv_leader, siv_follower);

        assert_eq!(cwk_leader, cwk_expected);
        assert_eq!(swk_leader, swk_expected);
        assert_eq!(civ_leader, civ_expected);
        assert_eq!(siv_leader, siv_expected);

        // client finished
        prf_leader.set_cf_hash(cf_hs_hash).unwrap();
        prf_follower.set_cf_hash(cf_hs_hash).unwrap();

        let cf_vd_leader = leader_prf_out.cf_vd;
        let cf_vd_follower = follower_prf_out.cf_vd;

        let mut cf_vd_leader = leader.decode(cf_vd_leader).unwrap();
        let mut cf_vd_follower = follower.decode(cf_vd_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let cf_vd_leader = cf_vd_leader.try_recv().unwrap().unwrap();
        let cf_vd_follower = cf_vd_follower.try_recv().unwrap().unwrap();

        assert_eq!(cf_vd_leader, cf_vd_follower);
        assert_eq!(cf_vd_leader, cf_vd_expected);

        // server finished
        prf_leader.set_sf_hash(sf_hs_hash).unwrap();
        prf_follower.set_sf_hash(sf_hs_hash).unwrap();

        let sf_vd_leader = leader_prf_out.sf_vd;
        let sf_vd_follower = follower_prf_out.sf_vd;

        let mut sf_vd_leader = leader.decode(sf_vd_leader).unwrap();
        let mut sf_vd_follower = follower.decode(sf_vd_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let sf_vd_leader = sf_vd_leader.try_recv().unwrap().unwrap();
        let sf_vd_follower = sf_vd_follower.try_recv().unwrap().unwrap();

        assert_eq!(sf_vd_leader, sf_vd_follower);
        assert_eq!(sf_vd_leader, sf_vd_expected);
    }
}
