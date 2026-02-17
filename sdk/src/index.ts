import {
    fetchCallReadOnlyFunction as callReadOnlyFunction,
    cvToValue,
    Cl,
    ReadOnlyFunctionOptions,
    makeContractCall
} from "@stacks/transactions";

export const SDK_VERSION = "0.1.0";
export const DEFAULT_CONTRACT_ADDRESS = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM"; // Mock devnet address
export const DEFAULT_CONTRACT_NAME = "stack-interop";

export interface StackInteropConfig {
    contractAddress: string;
    contractName: string;
    network?: "mainnet" | "testnet" | "devnet";
}

export class StackInteropSDK {
    private config: StackInteropConfig;

    constructor(config?: Partial<StackInteropConfig>) {
        this.config = {
            contractAddress: config?.contractAddress || DEFAULT_CONTRACT_ADDRESS,
            contractName: config?.contractName || DEFAULT_CONTRACT_NAME,
            network: config?.network || "devnet",
        };
    }

    public getContractIdentifier(): string {
        return `${this.config.contractAddress}.${this.config.contractName}`;
    }

    public getNetwork(): string {
        return this.config.network || "devnet";
    }

    public getConfig(): StackInteropConfig {
        return { ...this.config };
    }

    private getReadOnlyOptions(functionName: string, functionArgs: any[], senderAddress: string): ReadOnlyFunctionOptions {
        return {
            contractAddress: this.config.contractAddress,
            contractName: this.config.contractName,
            functionName,
            functionArgs,
            senderAddress,
            network: this.config.network || "devnet",
        };
    }

    public async fetchReputation(userAddress: string): Promise<any> {
        const options = this.getReadOnlyOptions("get-reputation", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchUserTier(userAddress: string): Promise<any> {
        const options = this.getReadOnlyOptions("get-user-tier", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchIdentity(userAddress: string): Promise<any> {
        const options = this.getReadOnlyOptions("get-identity", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchCompactIdentityData(userAddress: string): Promise<any> {
        const options = this.getReadOnlyOptions("get-compact-identity-data", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async isIdentityValid(userAddress: string): Promise<boolean> {
        const options = this.getReadOnlyOptions("is-identity-valid", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchVersion(): Promise<string> {
        const options = this.getReadOnlyOptions("get-version", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchTotalIdentities(): Promise<number> {
        const options = this.getReadOnlyOptions("get-total-identities", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchPausedStatus(): Promise<boolean> {
        const options = this.getReadOnlyOptions("get-paused-status", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchMaxIdentities(): Promise<number> {
        const options = this.getReadOnlyOptions("get-max-identities", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchVerificationCooldown(): Promise<number> {
        const options = this.getReadOnlyOptions("get-verification-cooldown", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchVerificationWindowStatus(): Promise<boolean> {
        const options = this.getReadOnlyOptions("get-verification-window-status", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchAuditLogEntry(index: number): Promise<any> {
        const options = this.getReadOnlyOptions("get-audit-log-entry", [Cl.uint(index)], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public async fetchAuditLogIndex(): Promise<number> {
        const options = this.getReadOnlyOptions("get-audit-log-index", [], DEFAULT_CONTRACT_ADDRESS);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }

    public buildLinkAddressOptions(btcPubkey: string, signature: string, messageHash: string) {
        return {
            contractAddress: this.config.contractAddress,
            contractName: this.config.contractName,
            functionName: "link-address",
            functionArgs: [
                Cl.bufferFromHex(btcPubkey),
                Cl.bufferFromHex(signature),
                Cl.bufferFromHex(messageHash)
            ],
        };
    }

    public buildRenewIdentityOptions() {
        return {
            contractAddress: this.config.contractAddress,
            contractName: this.config.contractName,
            functionName: "renew-identity",
            functionArgs: [],
        };
    }
}
