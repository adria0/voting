const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const bigInt = require("snarkjs").bigInt;
const assert = chai.assert;

const fpcensus = require("../src/franchiseproof").fpcensus;
const fpvoter = require("../src/franchiseproof").fpvoter;

describe("FranchiseProof", function () {
    this.timeout(200000);

    it("Test franchise proof", async () => {
        const voter = new fpvoter(
            1337,
            "0001020304050607080900010203040506070809000102030405060708090021"
        );
        const census = new fpcensus(10);
        await census.add(voter.idx,await voter.getPublicKeyHash());
        
        const poi        = await census.proofOfInclusion(voter.idx);
        const votingId   = bigInt(1);
        const voteValue  = bigInt(2);
        const input      = await voter.getInput(votingId,voteValue,poi);

        const cirDef = await compiler(path.join(__dirname, "circuits", "testfranchiseproof.circom"));
        circuit      = new snarkjs.Circuit(cirDef);
        const w = circuit.calculateWitness(input);
        assert(circuit.checkWitness(w));
    })

})