const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
//const bigInt = require("big-integer");
const createBlakeHash = require("blake-hash");
const bigInt = require("snarkjs").bigInt;

const mimc7 = require("circomlib").mimc7;
const smt = require("circomlib").smt;
const babyJub = require("circomlib").babyjub;
const eddsa = require("circomlib").eddsa;
const fs = require("fs");
const assert = chai.assert;

describe("test", function () {
    this.timeout(100000);

    it("BabyPbkFromPvk", async () => {    

        const rawpvk = Buffer.from("0001020304050607080900010203040506070809000102030405060708090021", "hex");
        const pvk    = createBlakeHash("blake512").update(rawpvk).digest().slice(0,32);
        const S      = bigInt.leBuff2int(pvk).shr(3);
        const A      = babyJub.mulPointEscalar(babyJub.Base8, S);

        const cirDef = await compiler(path.join(__dirname, "circuits", "testbabypbkfrompvk.circom"));
        circuit      = new snarkjs.Circuit(cirDef);

        const input = {
            in : S,
            Ax : A[0],
            Ay : A[1]
        }

        const w = circuit.calculateWitness(input);
        assert(circuit.checkWitness(w));
    })

    it("Voting", async () => {    

    })

/*
    it("test1", async () => {
        const msg = Buffer.from("00010203040506070809", "hex");
        const prvKey = Buffer.from("0001020304050607080900010203040506070809000102030405060708090001", "hex");
        const pubKey = eddsa.prv2pub(prvKey);
        const signature = eddsa.sign(prvKey, msg);
        const pSignature = eddsa.packSignature(signature);
        const uSignature = eddsa.unpackSignature(pSignature);
        assert(eddsa.verify(msg, uSignature, pubKey));
    })

    it("test2", async () => {
        const cirDef = await compiler(path.join(__dirname, "circuits", "testvoting.circom"));
        circuit = new snarkjs.Circuit(cirDef);
        console.log("NConstrains: " + circuit.nConstraints);

        const privateKey = bigInt("1020304050607080900010203040506070809000102030405060708090001");
        const votingId = bigInt("10203040506070809");
        const nullifier = mimc7.multiHash([privateKey, votingId])
        const input = {
            privateKey: privateKey,
            votingId: votingId,
            nullifier: nullifier
        }
        const w = circuit.calculateWitness(input);
        assert(circuit.checkWitness(w));

    });
    */
    /*   
           it("Should create a new tree for a new identity", async () => {
       
               const authorizeKeyClaim = iden3.buildClaim_AuthorizeKey({
                   publicKey: pubKey1
               });
               await userTree.insert(authorizeKeyClaim.hi, authorizeKeyClaim.hv);
       
               const userRootClaim = iden3.buildClaim_UserRoot({
                   idIdentity: idIdentity,
                   era: 0,
                   version: 0,
                   root: userTree.root
               });
       
               const res = await relayTree.insert(userRootClaim.hi, userRootClaim.hv);
       
               const m = mimc7.multiHash([bigInt("1234123412341234"),userRootClaim.hi, userRootClaim.hv ]);
               const signature = eddsa.signMiMC(prvKey1, m);
       
               const zeroSiblings10 = new Array(10).fill(0);
               let relayerInsert_siblings = res.siblings;
               while (relayerInsert_siblings.length<10) relayerInsert_siblings.push(bigInt(0));
       
               const input = {
                   oldRelayerRoot: res.oldRoot,
                   newRelayerRoot: res.newRoot,
                   oldUserRoot: 0,
                   idIdentity: idIdentity,
                   era: 0,
                   newUserRoot: res.newRoot,
                   newUserRootVersion: 0,
                   sigKeyX: pubKey1[0],
                   sigKeyY: pubKey1[1],
                   sigS: signature.S,
                   sigR8x: signature.R8[0],
                   sigR8y: signature.R8[1],
                   signingKeyInclussion_siblings: zeroSiblings10,
                   signingKeyExclusion_siblings: zeroSiblings10,
                   signingKeyExclusion_oldKey: 0,
                   signingKeyExclusion_oldValue: 0,
                   signingKeyExclusion_isOld0: 0,
                   oldRootInclusion_siblings: zeroSiblings10,
                   relayerInsert_siblings: relayerInsert_siblings,
                   relayerInsert_oldKey: res.isOld0 ? 0 : res.oldKey,
                   relayerInsert_oldValue: res.isOld0 ? 0 : res.oldValue,
                   relayerInsert_isOld0: res.isOld0 ? 1 : 0,
               };
       
               const w = circuit.calculateWitness(input);
       
               assert(circuit.checkWitness(w));
       
           });
       */
})