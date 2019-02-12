const fs = require("fs")
const path = require("path")
const { FPVoter, FPCensus } = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs")
const { bigInt } = zkSnark
const circom = require("circom")

///////////////////////////////////////////////////////////////////////////////
// BIG INT HELPERS

function stringifyBigInts(o) {
    if ((typeof (o) == "bigint") || (o instanceof bigInt)) {
        return o.toString(10)
    } else if (Array.isArray(o)) {
        return o.map(stringifyBigInts)
    } else if (typeof o == "object") {
        const res = {}
        for (let k in o) {
            res[k] = stringifyBigInts(o[k])
        }
        return res
    } else {
        return o
    }
}

function parseBigInts(o) {
    if ((typeof (o) == "string") && (/^[0-9]+$/.test(o))) {
        return bigInt(o)
    } else if (Array.isArray(o)) {
        return o.map(parseBigInts)
    } else if (typeof o == "object") {
        const res = {}
        for (let k in o) {
            res[k] = parseBigInts(o[k])
        }
        return res
    } else {
        return o
    }
}

///////////////////////////////////////////////////////////////////////////////

async function compileCircuit(filePath) {
    // compiles circuit ----------------------------------------------------------
    console.log("😺 compileCircuit() ...")
    console.time("😺 compileCircuit()")
    const cirDef = await circom(filePath)
    console.timeEnd("😺 compileCircuit()")
    return cirDef
}

function generateSetup(circuit) {
    // generate setup ----------------------------------------------------------
    console.log("😺 generateSetup() ...")
    console.time("😺 generateSetup()")
    // const circuitSource = parseBigInts(JSON.parse(fs.readFileSync("circuit.json", "utf8")))
    // const circuit = new zkSnark.Circuit(circuitSource)
    const protocol = "groth"
    if (!zkSnark[protocol]) throw new Error("Invalid protocol")

    const setup = zkSnark[protocol].setup(circuit)
    // fs.writeFileSync("proving_key.json", JSON.stringify(stringifyBigInts(setup.vk_proof), null, 1), "utf-8")
    // fs.writeFileSync("verification_key.json", JSON.stringify(stringifyBigInts(setup.vk_verifier), null, 1), "utf-8")
    console.timeEnd("😺 generateSetup()")
    return setup
}

async function generateWitness(circuit) {
    // ORGANIZER SIDE
    console.log("😺 generateWitness() ...")
    console.time("😺 generateWitness()")
    const voter = new FPVoter(
        1337,
        "0001020304050607080900010203040506070809000102030405060708090021"
    )
    const census = new FPCensus(20)
    await census.add(voter.idx, await voter.getPublicKeyHash())

    // VOTER SIDE
    const poi = await census.proofOfInclusion(voter.idx)
    const votingId = bigInt(1)
    const voteValue = bigInt(2)
    const input = await voter.getInput(votingId, voteValue, poi)

    const witness = circuit.calculateWitness(input)
    console.timeEnd("😺 generateWitness()")
    return witness
}

function checkWitness(circuit, witness) {
    console.log("😺 checkWitness ...")
    console.time("😺 checkWitness")
    if (!circuit.checkWitness(witness)) {
        throw new Error("Cannot verify witness")
    }
    console.timeEnd("😺 checkWitness")
}

function createProof(provingKey, witness) {
    // create proof ---------------------------------------------------------
    console.log("😺 createProof() ...")
    console.time("😺 createProof()")
    // const provingKey = parseBigInts(JSON.parse(fs.readFileSync("proving_key.json", "utf8")))
    const { protocol } = provingKey
    const { proof, publicSignals } = zkSnark[protocol].genProof(provingKey, witness)
    // fs.writeFileSync("proof.json", JSON.stringify(stringifyBigInts(proof), null, 1), "utf-8")
    // fs.writeFileSync("public_signals.json", JSON.stringify(stringifyBigInts(publicSignals), null, 1), "utf-8")
    console.timeEnd("😺 createProof()")

    return {
        proof,
        publicSignals
    }
}

function isProofValid(verificationKey, proof, publicSignals) {
    console.log("😺 isProofValid() ...")
    console.time("😺 isProofValid()")
    const verificationKeyProtocol = verificationKey.protocol
    const isValid = zkSnark[verificationKeyProtocol].isValid(verificationKey, proof, publicSignals)
    console.timeEnd("😺 isProofValid()")

    return isValid
}

////////////////////////////////////////////////////////////////////////////////

async function main() {
    console.log("This is going to take some time 😁 ")

    // COMPILE CIRCUIT
    let circuitSource
    if (fs.existsSync("circuit.json")) {
        // Stringify twice to ease the work of the bundler
        circuitSource = parseBigInts(JSON.parse(JSON.parse(fs.readFileSync("circuit.json", "utf8"))))
    }
    else {
        const filePath = path.join(__dirname, "./fp20.circom")
        circuitSource = await compileCircuit(filePath)

        // Two round stringified strings
        fs.writeFileSync("circuit.json", JSON.stringify(JSON.stringify(stringifyBigInts(circuitSource)), "utf-8"))
    }

    const circuit = new zkSnark.Circuit(circuitSource);

    // GENERATE SETUP
    let provingKey, verificationKey
    if (fs.existsSync("proving_key.json") && fs.existsSync("verification_key.json")) {
        // Stringify twice to ease the work of the bundler
        provingKey = parseBigInts(JSON.parse(JSON.parse(fs.readFileSync("proving_key.json", "utf8"))))
        verificationKey = parseBigInts(JSON.parse(JSON.parse(fs.readFileSync("verification_key.json", "utf8"))))
    }
    else {
        const setup = generateSetup(circuit)
        provingKey = setup.vk_proof
        verificationKey = setup.vk_verifier

        // Two round stringified strings
        fs.writeFileSync("proving_key.json", JSON.stringify(JSON.stringify(stringifyBigInts(provingKey)), "utf-8"))
        fs.writeFileSync("verification_key.json", JSON.stringify(JSON.stringify(stringifyBigInts(verificationKey)), "utf-8"))
    }

    // GENERATE WITNESS
    const witness = await generateWitness(circuit)

    // CHECK IT
    checkWitness(circuit, witness)

    // CREATE PROOF
    const { proof, publicSignals } = createProof(provingKey, witness)

    const validProof = isProofValid(verificationKey, proof, publicSignals)

    console.log("IS VALID:", validProof)
}

main()

