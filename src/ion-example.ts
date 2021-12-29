import { IonDid, IonKey, IonDocumentModel, IonPublicKeyPurpose, JwkEs256k, LocalSigner, IonPublicKeyModel, IonServiceModel, IonRequest } from "@decentralized-identity/ion-sdk";
import { EcPrivateKey } from "@decentralized-identity/did-auth-jose";
import { TextDecoder } from "util";
import multibase from "multibase";
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')
import { Wallet } from "ethers";
import sha3 from "js-sha3";

var decode = function (input: string) {
    // Replace non-url compatible chars with base64 standard chars
    input = input
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    // Pad out with standard base64 required padding characters
    var pad = input.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5 - pad).join('=');
    }

    return input;
}

function base64url(buffer: Uint8Array) {
    const decoder = new TextDecoder();
    const bytes = multibase.encode("base64url", buffer);
    return decoder.decode(bytes).slice(1);
}

function base64Decode(buffer: string) {
    const decoder = new TextDecoder();
    const bytes = multibase.decode(buffer);
    decoder.decode(bytes);
}

async function getPublicKey(privateKeyHex: string) {
    let hexToDecimal = (x: string) => ec.keyFromPrivate(x, "hex")

    const ec = new EC("secp256k1");
    const wallet = new Wallet(privateKeyHex);

    const privKey = ec.keyFromPrivate(privateKeyHex);

    let msg = 'Message for signing';
    let msgHash = sha3.keccak256(msg);
    let signature =
        ec.sign(msgHash, privKey, "hex", { canonical: true });

    const pubPoint = privKey.getPublic();

    const jwk = {
        kty: "EC",
        crv: "secp256k1",
        x: base64url(pubPoint.getX().toBuffer()),
        y: base64url(pubPoint.getY().toBuffer()),
    };

    return jwk;
}

async function hexToJWK(value: string) {
    value = value.replace("0x", "");

    // if (value.indexOf("04") == 0) {
    //     value = value.substring(2);
    // }

    return {
        kty: "EC",
        crv: "secp256k1",
        x: base64url(Buffer.from(value.substring(0, value.length / 2), "hex")),
        y: base64url(Buffer.from(value.substring(value.length / 2), "hex")),
    }
}

async function JWKToHex(value: { kty: string, crv: string, x: string, y: string }) {
    const b1 = Buffer.from(value.x, "base64");
    const b2 = Buffer.from(value.y, "base64");;

    return `${b1.toString("hex")}${b2.toString("hex")}`;
}

const createDID = async () => {
    // const r = await JWKToHex({
    //     kty: "",
    //     crv: "secp256k1",
    //     x: "hwQm6tCgx9DgGKfdmssIw5Y2sErH1Q6Erp0Faj37noeBiabPNKRiCLfRt44kNBUc",
    //     y: "E4YZemAko0Srt3Ek75-jq_v_22v7L1mQTO6tQcSO-c5YkIpE8NVInZW8Nyf-43p6"
    // });

    // const b = bs58;
    // const buff2 = Buffer.from("0429cae46d811b86009accd4c45e6c8545c84f1fe1871a683ad71c0a25d01789b008e7bedf62d88a535f827b677bf7c8cb8058306ee4fdd41eeff44ad938ae47d3", "hex");
    // const buff = Buffer.from(r, "hex");
    // const result = bs58.encode(buff);

    // const jwk2 = await hexToJWK("0429cae46d811b86009accd4c45e6c8545c84f1fe1871a683ad71c0a25d01789b008e7bedf62d88a535f827b677bf7c8cb8058306ee4fdd41eeff44ad938ae47d3");
    // const hex2 = await JWKToHex(jwk2);

    const privateKeyHex = '4bd22700ec3450b5f27e47ba70c233a680c981ab02c1432a859ae23111bef377';

    const jwk = await getPublicKey(privateKeyHex);
    // const publicKey = await parseJwk(jwk, "ES256K");

    // const ec = new EC("secp256k1");

    const kid = '#key-1';
    const privKey = await EcPrivateKey.generatePrivateKey(kid);
    const pubKey = privKey.getPublicKey();

    const doc: IonDocumentModel = {
        publicKeys: [{
            id: "publicKeyModel1Id",
            type: "EcdsaSecp256k1VerificationKey2019",
            publicKeyJwk: {
                kty: "EC",
                crv: "secp256k1",
                x: jwk.x,
                y: jwk.y
            },
            // publicKeyBase58: "oWZcRmUxJd1CHY1AtcLpgVKBJzj7u6bD2GyqPBGbzhKaXr6kMKhD6aq7u47aCxx4aLKTpKnwdmS6g4RgfGcrtgMpYvHTfht19MxK92cZktCbtgsZQBK7jQ8PHysaEXBrAid",
            purposes: [
                IonPublicKeyPurpose.Authentication
            ]
        }],
        services: undefined,
    }

    const didDoc = IonDid.createLongFormDid({
        document: doc,
        recoveryKey: {
            crv: 'secp256k1',
            kty: 'EC',
            x: (<any>pubKey).x,
            y: (<any>pubKey).y
        },
        updateKey: {
            crv: 'secp256k1',
            kty: 'EC',
            x: (<any>pubKey).x,
            y: (<any>pubKey).y
        },
    });

    console.log(didDoc);

    const request = IonRequest.createCreateRequest({
        document: doc,
        recoveryKey: {
            crv: 'secp256k1',
            kty: 'EC',
            x: (<any>pubKey).x,
            y: (<any>pubKey).y
        },
        updateKey: {
            crv: 'secp256k1',
            kty: 'EC',
            x: (<any>pubKey).x,
            y: (<any>pubKey).y
        },
    });

    console.log(request);
}

const consumeDID = async () => {

}


createDID();

export interface ExtendedIonPublicKeyModel extends IonPublicKeyModel {
    publicKeyBase58: string;
}

export interface ExtendedIonDocumentModel extends IonDocumentModel {
    // publicKeyHex?: string;
}