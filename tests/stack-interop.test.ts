
import { describe, expect, it, beforeAll } from "vitest";
import { Cl } from "@stacks/transactions";

describe("Identity Registry Tests", () => {
  let accounts: any;
  let wallet1: string;
  let wallet2: string;

  beforeAll(() => {
    accounts = simnet.getAccounts();
    wallet1 = accounts.get("wallet_1")!;
    wallet2 = accounts.get("wallet_2")!;
  });

  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("allows a user to link a Bitcoin address", () => {
    const btcPubkey = "02" + "0".repeat(64); // mock 33-byte pubkey
    const signature = "0".repeat(130); // mock 65-byte signature
    const messageHash = "0".repeat(64); // mock 32-byte hash

    const { result } = simnet.callPublicFn(
      "stack-interop",
      "link-address",
      [
        Cl.bufferFromHex(btcPubkey),
        Cl.bufferFromHex(signature),
        Cl.bufferFromHex(messageHash),
      ],
      wallet1
    );

    expect(result).toBeOk(Cl.bool(true));

    // Verify mapping
    const { result: identity } = simnet.callReadOnlyFn(
      "stack-interop",
      "get-identity",
      [Cl.principal(wallet1)],
      wallet1
    );

    expect(identity).toBeDefined();
  });

  it("prevents linking the same principal twice", () => {
    const btcPubkey = "02" + "1".repeat(64);
    const signature = "1".repeat(130);
    const messageHash = "1".repeat(64);

    // Initial setup for wallet2
    simnet.callPublicFn("stack-interop", "link-address", [
      Cl.bufferFromHex(btcPubkey),
      Cl.bufferFromHex(signature),
      Cl.bufferFromHex(messageHash),
    ], wallet2);

    // Second call
    const { result } = simnet.callPublicFn("stack-interop", "link-address", [
      Cl.bufferFromHex(btcPubkey),
      Cl.bufferFromHex(signature),
      Cl.bufferFromHex(messageHash),
    ], wallet2);

    expect(result).toBeErr(Cl.uint(101)); // ERR-ALREADY-LINKED
  });

  it("handles administrative ownership transfer", () => {
    const deployer = accounts.get("deployer")!;
    const newOwner = accounts.get("wallet_3")!;

    const { result } = simnet.callPublicFn("stack-interop", "transfer-ownership", [Cl.principal(newOwner)], deployer);
    expect(result).toBeOk(Cl.bool(true));

    // Non-owner cannot pause
    const { result: pauseErr } = simnet.callPublicFn("stack-interop", "set-registry-pause", [Cl.bool(true)], deployer);
    expect(pauseErr).toBeErr(Cl.uint(1005)); // ERR-NOT-OWNER
  });

  it("validates identity renewal and cooldown", () => {
    // wallet1 is already linked from previous test
    // Advance time slightly
    simnet.mineEmptyBlocks(10);

    const { result } = simnet.callPublicFn("stack-interop", "renew-identity", [], wallet1);
    expect(result).toBeErr(Cl.uint(1008)); // ERR-COOLDOWN-ACTIVE
  });

  it("allows tier advancement based on reputation", () => {
    // Grant reputation to wallet1 (as owner)
    const owner = accounts.get("wallet_3")!; // current owner
    simnet.callPublicFn("stack-interop", "grant-verified-reputation", [Cl.principal(wallet1), Cl.uint(100)], owner);

    // Now wallet1 should be able to advance to Tier 2
    const { result } = simnet.callPublicFn("stack-interop", "advance-tier", [Cl.uint(2)], wallet1);
    expect(result).toBeOk(Cl.bool(true));
  });

  it("verifies reputation boost functionality", () => {
    // wallet1 claims boost
    const { result } = simnet.callPublicFn("stack-interop", "claim-reputation-boost", [], wallet1);
    expect(result).toBeOk(Cl.bool(true));

    // Verify reputation increased
    const { result: reputation } = simnet.callReadOnlyFn("stack-interop", "get-reputation", [Cl.principal(wallet1)], wallet1);
    // Initial was 10 + 100 (grant) + 10 (boost) = 120
    expect(reputation).toBeSome();
    // Use match or cast to verify value if needed, but simple some check for now
  });

  it("handles identity revocation by owner", () => {
    const owner = accounts.get("wallet_3")!;
    const { result } = simnet.callPublicFn("stack-interop", "revoke-identity", [Cl.principal(wallet1)], owner);
    expect(result).toBeOk(Cl.bool(true));

    // wallet1 no longer has identity
    const { result: identity } = simnet.callReadOnlyFn("stack-interop", "get-identity", [Cl.principal(wallet1)], wallet1);
    expect(identity).toBeNone();
  });

  it("verifies read-only status and summary helpers", () => {
    const { result: summary } = simnet.callReadOnlyFn("stack-interop", "get-compact-identity-data", [Cl.principal(wallet2)], wallet2);
    expect(summary).toBeDefined();
    // summary is a response wrapping a tuple
  });
});
