// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  ForensiZKCircuit
 * @notice Solidity mirror of ForensiZK's Plonky2 circuit (prover/src/circuit.rs).
 *
 * This contract translates the Rust/Plonky2 boolean constraint system into
 * Solidity so it can be formally verified using Foundry (fuzz) + Halmos (symbolic).
 *
 * Circuit inputs — match witness.rs Features struct:
 *   ssh_failed  — count of SSH failed logins, 8-bit range [0..255]
 *   shadow      — /etc/shadow or sensitive file access detected
 *   tmp_exec    — execution from /tmp, /var/tmp, /dev/shm detected
 *   outbound    — outbound shell / reverse shell connection detected
 *   kernel      — kernel fault / segfault / OOM detected
 *   net_flap    — network interface instability detected
 *
 * Circuit output:
 *   compromised — true if ANY indicator is present
 */
contract ForensiZKCircuit {

    // ── Constants (mirror circuit.rs) ───────────────────────────────────────
    uint8  public constant SSH_BRUTE_THRESHOLD = 5;   // ssh_failed >= 5 → brute force
    uint8  public constant SSH_BITS            = 8;   // 8-bit range: max value 255

    // ── Core circuit function ────────────────────────────────────────────────
    /**
     * @notice Evaluates the forensic circuit for a given witness.
     *         Mirrors prove_circuit() boolean logic in circuit.rs.
     * @return compromised true if the system log indicates compromise
     */
    function evaluate(
        uint8 ssh_failed,
        bool  shadow,
        bool  tmp_exec,
        bool  outbound,
        bool  kernel,
        bool  net_flap
    ) public pure returns (bool compromised) {
        // SSH brute-force gate (mirrors bits[2..7] OR chain in circuit.rs)
        bool ssh_brute = (ssh_failed >= SSH_BRUTE_THRESHOLD);

        // OR gate over all forensic flags (mirrors builder.or chain)
        compromised = ssh_brute
                   || shadow
                   || tmp_exec
                   || outbound
                   || kernel
                   || net_flap;
    }

    // ── Bit decomposition consistency ────────────────────────────────────────
    /**
     * @notice Mirrors circuit.rs:
     *         let bits = builder.split_le(ssh_target, SSH_BITS);
     *         let reconstructed = builder.le_sum(bits.iter());
     *         builder.connect(ssh_target, reconstructed);
     *
     *         For any uint8, splitting into 8 bits and re-assembling
     *         must always equal the original value.
     */
    function bitDecompositionConsistent(uint8 value) public pure returns (bool) {
        uint8 reconstructed = 0;
        for (uint8 i = 0; i < 8; i++) {
            uint8 bit = (value >> i) & 1;
            reconstructed |= (bit << i);
        }
        return reconstructed == value;
    }

    // ── SSH threshold boundary helper ────────────────────────────────────────
    /**
     * @notice Returns whether ssh_failed is at or above the brute force threshold.
     *         Used to isolate the threshold gate in targeted tests.
     */
    function isSSHBruteForce(uint8 ssh_failed) public pure returns (bool) {
        return ssh_failed >= SSH_BRUTE_THRESHOLD;
    }
}
