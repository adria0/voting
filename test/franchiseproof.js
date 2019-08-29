const chai = require("chai");
const path = require("path");
const snarkjs = require("../node_modules/snarkjs");
const compiler = require("../node_modules/circom");
const bigInt = require("../node_modules/snarkjs").bigInt;
const assert = chai.assert;

const { FPCensus, FPVoter } = require("../src/franchiseproof");

describe("FranchiseProof", function () {
    this.timeout(200000);

    it("Test franchise proof", async () => {
        const voter = new FPVoter(
            1337,
            "0001020304050607080900010203040506070809000102030405060708090021"
        );
        const census = new FPCensus(10);
        await census.add(voter.idx, await voter.getPublicKeyHash());

        const poi = await census.proofOfInclusion(voter.idx);
        const votingId = bigInt(1);
        const voteValue = bigInt(2);
        const input = await voter.getInput(votingId, voteValue, poi);

        const cirDef = await compiler(
		path.join(__dirname, "circuits", "testfranchiseproof.circom"),
		{ reduceConstraints: false}
	);
        circuit = new snarkjs.Circuit(cirDef);
	    const w = circuit.calculateWitness(input);
        assert(circuit.checkWitness(w));
    })

})
