const fs = require("fs")
const path = require("path");
const fp = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs");
const bigInt = require("snarkjs").bigInt;
const circom = require("circom");

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

    console.log("this is gonna take some time 😁 ")

    // compiles circuit ----------------------------------------------------------
    console.log("😺 compile_circuit...")
    console.time("😺 compile_circuit")
    const cirDef = await circom(path.join(__dirname,"./fp20.circom"));
    fs.writeFileSync("circuit.json", JSON.stringify(stringifyBigInts(cirDef), null, 1), "utf-8");
    console.timeEnd("😺 compile_circuit")

    // generate setup ----------------------------------------------------------
    console.log("😺 generate_setup...")
    console.time("😺 generate_setup")
    const circuitSource = unstringifyBigInts(JSON.parse(fs.readFileSync("circuit.json", "utf8")))
    const circuit = new zkSnark.Circuit(circuitSource);
    const protocol = "groth";
    if (!zkSnark[protocol]) throw new Error("Invalid protocol");
    
    const setup = zkSnark[protocol].setup(circuit);
    fs.writeFileSync("proving_key.json", JSON.stringify(stringifyBigInts(setup.vk_proof), null, 1), "utf-8");
    fs.writeFileSync("verification_key.json", JSON.stringify(stringifyBigInts(setup.vk_verifier), null, 1), "utf-8");
    console.timeEnd("😺 generate_setup")
    
    // generate witness ------------------------------------------------------
    console.log("😺 generate_witness...");
    console.time("😺 generate_witness");
    const voter = new fp.fpvoter(
        1337,
        "0001020304050607080900010203040506070809000102030405060708090021"
    );
    const census = new fp.fpcensus(20);
    await census.add(voter.idx,await voter.getPublicKeyHash());

    const poi        = await census.proofOfInclusion(voter.idx);
    const votingId   = bigInt(1);
    const voteValue  = bigInt(2);
    const input      = await voter.getInput(votingId,voteValue,poi);

    const witness = circuit.calculateWitness(input);
    console.timeEnd("😺 generate_witness");

    // verify witness -------------------------------------------------------
    console.log("😺 check_witness...");
    console.time("😺 check_witness");
    if (!circuit.checkWitness(witness)) throw new Error("cannot verify witness");
    console.timeEnd("😺 check_witness");

    // create proof ---------------------------------------------------------
    console.log("😺 creating_proof...");
    console.time("😺 creating_proof");
    const provingKey = unstringifyBigInts(JSON.parse(fs.readFileSync("proving_key.json", "utf8")))
    const provingKeyProtocol= provingKey.protocol;
    const {proof, publicSignals} = zkSnark[provingKeyProtocol].genProof(provingKey, witness);
    fs.writeFileSync("proof.json", JSON.stringify(stringifyBigInts(proof), null, 1), "utf-8");
    fs.writeFileSync("public_signals.json", JSON.stringify(stringifyBigInts(publicSignals), null, 1), "utf-8");
    console.timeEnd("😺 creating_proof");

    // verify proof ---------------------------------------------------------
    console.log("😺 verify_proof...");
    console.time("😺 verify_proof");
    const verificationKey = unstringifyBigInts(JSON.parse(fs.readFileSync("verification_key.json", "utf8")));
    const verificationKeyProtocol = verificationKey.protocol;
    const isValid = zkSnark[verificationKeyProtocol].isValid(verificationKey, proof, publicSignals);
    console.timeEnd("😺 verify_proof");

    console.log("proof ok ",isValid);
}

demo()
