const fs = require("fs")
const fp = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs");
const bigInt = require("snarkjs").bigInt;

function stringifyBigInts(o) {
    if ((typeof(o) == "bigint") || (o instanceof bigInt))  {
        return o.toString(10);
    } else if (Array.isArray(o)) {
        return o.map(stringifyBigInts);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = stringifyBigInts(o[k]);
        }
        return res;
    } else {
        return o;
    }
}

function unstringifyBigInts(o) {
    if ((typeof(o) == "string") && (/^[0-9]+$/.test(o) ))  {
        return bigInt(o);
    } else if (Array.isArray(o)) {
        return o.map(unstringifyBigInts);
    } else if (typeof o == "object") {
        const res = {};
        for (let k in o) {
            res[k] = unstringifyBigInts(o[k]);
        }
        return res;
    } else {
        return o;
    }
}

async function demo(){

    // read circuit ----------------------------------------------------------
    console.time("😺 load_circuit")
    const cirDef = JSON.parse(fs.readFileSync("circuit.json", "utf8"));
    const circuit = new zkSnark.Circuit(cirDef);
    console.timeEnd("😺 load_circuit")
    
    // generate witness ------------------------------------------------------
    console.time("😺 generate_witness");
    const voter = new fp.fpvoter(
        1337,
        "0001020304050607080900010203040506070809000102030405060708090021"
    );
    const census = new fp.fpcensus(140);
    await census.add(voter.idx,await voter.getPublicKeyHash());

    const poi        = await census.proofOfInclusion(voter.idx);
    const votingId   = bigInt(1);
    const voteValue  = bigInt(2);
    const input      = await voter.getInput(votingId,voteValue,poi);

    const witness = circuit.calculateWitness(input);
    console.timeEnd("😺 generate_witness");

    // verify witness -------------------------------------------------------
    console.time("😺 check_witness");
    if (!circuit.checkWitness(witness)) {
    	console.log("cannot verify witness");
	    return;
    }
    console.timeEnd("😺 check_witness");

    // create proof ---------------------------------------------------------
    console.time("😺 creating_proof");
    const provingKey = unstringifyBigInts(JSON.parse(fs.readFileSync("proving_key.json", "utf8")))
    const provingKeyProtocol= provingKey.protocol;
    const {proof, publicSignals} = zkSnark[provingKeyProtocol].genProof(provingKey, witness);
    fs.writeFileSync("proof.json", JSON.stringify(stringifyBigInts(proof), null, 1), "utf-8");
    fs.writeFileSync("public_signals.json", JSON.stringify(stringifyBigInts(publicSignals), null, 1), "utf-8");
    console.timeEnd("😺 creating_proof");

    // verify proof ---------------------------------------------------------
    console.time("😺 verify_proof");
    const verificationKey = unstringifyBigInts(JSON.parse(fs.readFileSync("verification_key.json", "utf8")));
    const verificationKeyProtocol = verificationKey.protocol;
    const isValid = zkSnark[verificationKeyProtocol].isValid(verificationKey, proof, publicSignals);
    console.timeEnd("😺 verify_proof");

    console.log("proof ok ",isValid);
}

demo()
