import { Address } from '../crypto/address';
import { Account } from './account';
import { Identity } from './identity';
import { ScryptOptionsEx } from './scrypt';
export declare class Wallet {
    static constructAddress(address: string | Address): Address;
    static create(): Wallet;
    static deserializeJson(obj: any): Wallet;
    name: string;
    defaultTstid: string;
    defaultAccountAddress: string;
    createTime: string;
    version: string;
    scrypt: ScryptOptionsEx;
    keyLength: number;
    identities: Identity[];
    accounts: Account[];
    extra: null;
    addAccount(account: Account): void;
    delAccount(address: string | Address): void;
    getAccount(address: string | Address): Account | undefined;
    addIdentity(identity: Identity): void;
    delIdentity(tstid: string): void;
    getIdentity(tstid: string): Identity | undefined;
    setDefaultAccount(address: string): void;
    setDefaultIdentity(tstid: string): void;
    /**
     * Serializes to JSON object.
     *
     *
     */
    serializeJson(stringify?: boolean): any;
}
