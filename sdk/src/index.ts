import {
    callReadOnlyFunction,
    cvToValue,
    Cl,
    ReadOnlyFunctionOptions
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
        };
    }

    public async fetchReputation(userAddress: string): Promise<any> {
        const options = this.getReadOnlyOptions("get-reputation", [Cl.principal(userAddress)], userAddress);
        const result = await callReadOnlyFunction(options);
        return cvToValue(result);
    }
}
