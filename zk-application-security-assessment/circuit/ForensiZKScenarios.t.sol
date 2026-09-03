// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ForensiZKCircuit.sol";

/**
 * @title  ForensiZKScenarios
 * @notice Concrete scenario tests derived from real log files in the project.
 *         Each test encodes a specific log → expected verdict mapping.
 *
 * Run with:
 *   forge test --match-contract ForensiZKScenarios -vvv
 */
contract ForensiZKScenarios is Test {

    ForensiZKCircuit circuit;

    function setUp() public {
        circuit = new ForensiZKCircuit();
    }

    // ── Scenario 1: test.log from backend/uploads ────────────────────────────
    // Log contains:
    //   "Unauthorized attempt to access /etc/shadow blocked" → shadow=true
    //   "EXT4-fs error (device sda1): ext4_find_entry"      → kernel=true
    //   SSH failures < 5
    function test_Scenario_ShadowAndKernel() public view {
        assertTrue(
            circuit.evaluate(2, true, false, false, true, false),
            "Shadow access + kernel fault = compromised"
        );
    }

    // ── Scenario 2: Pure SSH brute force ─────────────────────────────────────
    // 6 consecutive Failed password entries, no other indicators
    function test_Scenario_BruteForceOnly() public view {
        assertTrue(
            circuit.evaluate(6, false, false, false, false, false),
            "6 SSH failures = brute force = compromised"
        );
    }

    // ── Scenario 3: Clean system ──────────────────────────────────────────────
    // Normal login accepted, no anomalies
    function test_Scenario_CleanLogin() public view {
        assertFalse(
            circuit.evaluate(0, false, false, false, false, false),
            "Normal accepted login = not compromised"
        );
    }

    // ── Scenario 4: Outbound reverse shell ───────────────────────────────────
    // curl to attacker IP detected
    function test_Scenario_ReverseShell() public view {
        assertTrue(
            circuit.evaluate(0, false, false, true, false, false),
            "Outbound reverse shell = compromised"
        );
    }

    // ── Scenario 5: Full attack chain ────────────────────────────────────────
    // Brute force + shadow + reverse shell (APT scenario)
    function test_Scenario_FullAttack() public view {
        assertTrue(
            circuit.evaluate(8, true, true, true, false, false),
            "Full attack chain = compromised"
        );
    }

    // ── Scenario 6: F-04 boundary — 4 failures (just below threshold) ────────
    function test_Scenario_BelowBruteForceThreshold() public view {
        assertFalse(
            circuit.evaluate(4, false, false, false, false, false),
            "4 SSH failures = NOT brute force (threshold is 5)"
        );
    }

    // ── Scenario 7: F-04 boundary — exactly 5 failures ───────────────────────
    function test_Scenario_ExactlyAtBruteForceThreshold() public view {
        assertTrue(
            circuit.evaluate(5, false, false, false, false, false),
            "5 SSH failures = brute force threshold reached"
        );
    }

    // ── Scenario 8: Kernel fault only ────────────────────────────────────────
    function test_Scenario_KernelFaultOnly() public view {
        assertTrue(
            circuit.evaluate(0, false, false, false, true, false),
            "Kernel fault alone = compromised"
        );
    }

    // ── Scenario 9: Network instability only ─────────────────────────────────
    function test_Scenario_NetFlapOnly() public view {
        assertTrue(
            circuit.evaluate(0, false, false, false, false, true),
            "Network instability alone = compromised"
        );
    }

    // ── Scenario 10: Tmp execution only ──────────────────────────────────────
    function test_Scenario_TmpExecOnly() public view {
        assertTrue(
            circuit.evaluate(0, false, true, false, false, false),
            "Execution from /tmp alone = compromised"
        );
    }
}
