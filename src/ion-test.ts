import { IonDid, IonKey, IonDocumentModel, IonPublicKeyPurpose, JwkEs256k, LocalSigner, IonPublicKeyModel, IonServiceModel, IonRequest, IonSdkConfig, IonNetwork } from "@decentralized-identity/ion-sdk";
import { EcPrivateKey } from "@decentralized-identity/did-auth-jose";
import { TextDecoder } from "util";
import multibase from "multibase";
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')
import { Wallet } from "ethers";
import sha3 from "js-sha3";
import { Base, BaseConverter, VerificationMethodJwk } from "./base-converter";
import fetch from "node-fetch";
import { updateIndexedAccessTypeNode } from "typescript";
// import fetch from "node-fetch";

function base64url(buffer: Uint8Array) {
    const decoder = new TextDecoder();
    const bytes = multibase.encode("base64url", buffer);
    return decoder.decode(bytes).slice(1);
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


var testDID = async () => {
    const pbk = "0x04b921126705b5506673c000a3224ce6101adf713b8a5c291737f5ab8955e05bdf0a0d4fd88594d434efd5a82ced0e9337efcdae5dc969f19eab20385ddfafd1cf";

    const publicKeyJWK = BaseConverter.convert(pbk, Base.Hex, Base.JWK)
    const privateKeyJWK = BaseConverter.convert(pbk, Base.Hex, Base.JWK)

    const updateKey = publicKeyJWK as JwkEs256k;
    const recoveryKey = publicKeyJWK as JwkEs256k;
    const services = new Array<IonServiceModel>();

    const initialDidDocument = {
        publicKeys: [{
            verificationMethod: {
                controller: '',
                type: 'EcdsaSecp256k1VerificationKey2019',
                id: 'bbsbls2020',
                publicKeyBase58: 'rj9GLNeWQPYvSse3Pn5TjrdSLjXWQrNnEhqkFQKu857Shj3RVdh1RbzTypwSuVaGtXZ4PBPdx7tA2MiyMh25ouwm6Dhp2igNY2HKfQvwDPBDGLG4QytM5eQkRgNN2moVUMt'
            },
            verificationRelationship: ["authentication"]
        }]
    }
    const publicKeys = initialDidDocument.publicKeys.map(x => {
        const vm = BaseConverter.convertVM(x.verificationMethod, Base.JWK) as VerificationMethodJwk;
        let ionModel: IonPublicKeyModel = {
            id: vm.id,
            publicKeyJwk: vm.publicKeyJwk,
            type: vm.type,
            purposes: [IonPublicKeyPurpose.Authentication]
        };
        return ionModel;
    });

    // IonSdkConfig.network = IonNetwork.Testnet;


    const document: IonDocumentModel = {
        publicKeys: publicKeys,
        services
    }

    const didDoc = IonDid.createLongFormDid({
        document: document,
        recoveryKey: recoveryKey,
        updateKey: updateKey,
    });

    const input = { recoveryKey, updateKey, document }
    const result = IonRequest.createCreateRequest(input)

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };


    // let ionCoreEndpoint = "https://saas.extrimian.com/ion-testnet";
    let ionCoreEndpoint = "http://localhost:3005";

    let response = await fetch(`${ionCoreEndpoint}/operations`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    return (await response.json() as any).didDocumentMetadata.canonicalId;
}

const createKey = async () => {
    const recoveryKey = require('./keys/jwkEs256k1Public.json');
    const updateKey = require('./keys/jwkEs256k2Public.json');
    const publicKey = require('./keys/publicKeyModel1.json');

    // const pk = BaseConverter.convert(updateKey, Base.JWK, Base.Hex);
    // var jwk = BaseConverter.convert("0xc1fc10089dce46a55d9c75e44fc3fe2e0fc6b71044857dedcbd3549f09c7ae6cba27bca8bfd5b809d10ddba9859bb12ceeaa4fd90fa77291184211953a56adf5", Base.Hex, Base.JWK);

    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');
    // const services = [service];

    const document: IonDocumentModel = {
        publicKeys,
        services
    };
    const input = { recoveryKey, updateKey, document };
    const result = IonRequest.createCreateRequest(input);

    const didDoc = IonDid.createLongFormDid({
        document: document,
        recoveryKey: recoveryKey,
        updateKey: updateKey,
    });

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://20.237.2.83/";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (await response.json() as any).didDocumentMetadata.canonicalId;

    console.log(canonicalId);
}

const create2Key = async () => {
    const recoveryKey = require('./keys/jwkEs256k2Public.json');
    const updateKey = require('./keys/jwkEs256k1Public.json');
    const publicKey = require('./keys/publicKeyModel1.json');

    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');
    // const services = [service];

    const document: IonDocumentModel = {
        publicKeys,
        services
    };
    const input = { recoveryKey, updateKey, document };
    const result = IonRequest.createCreateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3005";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    const canonicalId = (await response.json() as any).didDocumentMetadata.canonicalId;

    console.log(canonicalId);
}

const updateKey = async () => {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');
    const input = {
        didSuffix: 'EiBDvFE0jvl4TvGCAIM3IF-9plhcvND3iD1qxprRTlYh5A',
        updatePublicKey: require('./keys/jwkEs256k1Public.json'),
        nextUpdatePublicKey: require('./keys/jwkEs256k1Public.json'),
        // require('./keys/jwkEs256k1Public.json'),
        // nextUpdatePublicKey: require('./keys/jwkEs256k2Public.json'),
        signer: LocalSigner.create(require('./keys/jwkEs256k2Private.json')),
        servicesToAdd: services,
        idsOfServicesToRemove: ['service5Id'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['publicKeyModel2Id']
    };

    const result = await IonRequest.createUpdateRequest(input);

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3000";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    // const body = await response.json();
    // return body.didDocumentMetadata.canonicalId;
}

const recoveryKey = async () => {
    const publicKey = require('./keys/publicKeyModel1.json');
    const publicKeys = [publicKey];

    const services = require('./keys/service1.json');

    const document: IonDocumentModel = {
        publicKeys,
        services
    };

    const result = await IonRequest.createRecoverRequest({
        didSuffix: 'EiBDvFE0jvl4TvGCAIM3IF-9plhcvND3iD1qxprRTlYh5A',
        recoveryPublicKey: require('./keys/jwkEs256k1Public.json'),
        nextRecoveryPublicKey: require('./keys/jwkEs256k2Public.json'),
        nextUpdatePublicKey: require('./keys/jwkEs256k3Public.json'),
        document,
        signer: LocalSigner.create(require('./keys/jwkEs256k1Private.json'))
    });

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(result)
    };

    let ionCoreEndpoint = "http://localhost:3000";

    let response = await fetch(`${ionCoreEndpoint}`, options)
    if (response.status != 200 && response.status != 201) {
        const msg = await response.json();
        throw new Error(`Ion DID creation is not ok: ${msg}`);
    }
    return (await response.json() as any).didDocumentMetadata.canonicalId;
}

createKey();
// create2Key();