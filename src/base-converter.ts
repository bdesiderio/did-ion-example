import multibase from "multibase";
import bs58 from "bs58"
import { TextDecoder } from "util";
// import { VerificationMethod } from "did-resolver";

export enum VerificationMethodTypes {
    Ed25519VerificationKey2018 = "Ed25519VerificationKey2018",
    EcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019",
    X25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019",
    JsonWebKey2020 = "JsonWebKey2020",
    GpgVerificationKey2020 = "GpgVerificationKey2020",
    Bls12381G1Key2020 = "Bls12381G1Key2020",
}

export class VerificationMethodHelper {
    static getVMValue(vm: VerificationMethod) {
        if ((<VerificationMethodPublicKey58>vm).publicKeyBase58 != null) {
            return (<VerificationMethodPublicKey58>vm).publicKeyBase58;
        }
        else if ((<VerificationMethodPublicKeyHex>vm).publicKeyHex != null) {
            return (<VerificationMethodPublicKeyHex>vm).publicKeyHex;
        }
        else if ((<VerificationMethodGpg>vm).publicKeyGpg != null) {
            return (<VerificationMethodGpg>vm).publicKeyGpg;
        }
    }
}

export interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
}

export interface VerificationMethodPublicKeyHex extends VerificationMethod {
    type: VerificationMethodTypes.Ed25519VerificationKey2018 | VerificationMethodTypes.Bls12381G1Key2020 | VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019;
    publicKeyHex: string;
}

export interface VerificationMethodPublicKey58 extends VerificationMethod {
    type: VerificationMethodTypes.Ed25519VerificationKey2018 | VerificationMethodTypes.Bls12381G1Key2020 | VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019;
    publicKeyBase58: string;
}

export interface VerificationMethodGpg extends VerificationMethod {
    type: VerificationMethodTypes.GpgVerificationKey2020;
    publicKeyGpg: string;
}

export interface VerificationMethodJwk extends VerificationMethod {
    type: VerificationMethodTypes.JsonWebKey2020 | VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019;

    publicKeyJwk: {
        crv: string;
        x: string;
        y: string;
        kty: string;
        kid?: string;
    };
}

export enum Base {
    Hex = "hex",
    Base58 = "base58",
    Base64 = "base64",
    JWK = "jwk",
}

export class BaseConverterVM {
    static convertVM(verificationMethod: VerificationMethod, toBase: Base) {
        //////////////// Hex <-> JWK
        if ((<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex && toBase == Base.JWK)
            (<VerificationMethodJwk>verificationMethod).publicKeyJwk =
                this.convert((<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex, Base.Hex, Base.JWK) as {
                    crv: string;
                    x: string;
                    y: string;
                    kty: string;
                };

        if ((<VerificationMethodJwk>verificationMethod).publicKeyJwk && toBase == Base.Hex)
            (<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex =
                this.convert((<VerificationMethodJwk>verificationMethod).publicKeyJwk, Base.Hex, Base.JWK) as string;

        /////////////////////////////// Base58 <-> JWK

        if ((<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58 && toBase == Base.JWK)
            (<VerificationMethodJwk>verificationMethod).publicKeyJwk =
                this.convert((<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58, Base.Base58, Base.JWK) as {
                    crv: string;
                    x: string;
                    y: string;
                    kty: string;
                };

        if ((<VerificationMethodJwk>verificationMethod).publicKeyJwk && toBase == Base.Base58)
            (<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58 =
                this.convert((<VerificationMethodJwk>verificationMethod).publicKeyJwk, Base.JWK, Base.Base58) as string;

        /////////////////////////////// Base58 <-> HEX

        if ((<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58 && toBase == Base.Hex)
            (<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex =
                this.convert((<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58, Base.Base58, Base.Hex) as string;

        if ((<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex && toBase == Base.Base58)
            (<VerificationMethodPublicKey58>verificationMethod).publicKeyBase58 =
                this.convert((<VerificationMethodPublicKeyHex>verificationMethod).publicKeyHex, Base.Hex, Base.Base58) as string;

        return verificationMethod;
    }

    static convert(value: any, fromBase: Base, toBase: Base) {
        if (fromBase == Base.Base58 && toBase == Base.Hex) {
            return bs58.decode(value).toString("hex");
        }
        if (fromBase == Base.Hex && toBase == Base.Base58) {
            return bs58.encode(Buffer.from(value, "hex"));
        }
        if (fromBase == Base.Hex && toBase == Base.JWK) {
            return this.hexToJWK(value);
        }
        if (fromBase == Base.JWK && toBase == Base.Hex) {
            return this.JWKToHex(value);
        }
        if (fromBase == Base.Base58 && toBase == Base.JWK) {
            return this.hexToJWK(bs58.decode(value).toString("hex"));
        }
        if (fromBase == Base.JWK && toBase == Base.Base58) {
            return bs58.encode(Buffer.from(this.JWKToHex(value), "hex"));
        }
    }

    private static hexToJWK(value: string) {
        value = value.replace("0x", "");

        // if (value.indexOf("04") == 0) {
        //     value = value.substring(2);
        // }

        return {
            // kid: "",
            kty: "EC",
            crv: "secp256k1",
            x: this.base64url(Buffer.from(value.substring(0, value.length / 2), "hex")),
            y: this.base64url(Buffer.from(value.substring(value.length / 2), "hex")),
        }
    }

    private static base64url(buffer: Uint8Array) {
        const decoder = new TextDecoder();
        const bytes = multibase.encode("base64url", buffer);
        return decoder.decode(bytes).slice(1);
    }

    private static JWKToHex(value: { kty: string, crv: string, x: string, y: string }) {
        const b1 = Buffer.from(value.x, "base64url");
        const b2 = Buffer.from(value.y, "base64url");;

        // return `0x04${b1.toString("hex")}${b2.toString("hex")}`;
        return `0x${b1.toString("hex")}${b2.toString("hex")}`;
    }
}