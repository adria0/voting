const fs = require("fs")
const path = require("path")
const { FPVoter, FPCensus } = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs")
const { bigInt, Circuit } = zkSnark
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
// DATA EN/DECODING HELPERS

function serializeData(payload, filePath) {
    if (!payload) throw new Error("Empty payload")
    else if (!filePath) throw new Error("Empty file path")

    // Stringify twice to ease the work of the bundler
    fs.writeFileSync(filePath, JSON.stringify(JSON.stringify(stringifyBigInts(payload)), "utf-8"))
}

function deserializeData(filePath) {
    if (!fs.existsSync(filePath)) throw new Error("The file does not exist")

    // Two round stringified strings
    return parseBigInts(JSON.parse(JSON.parse(fs.readFileSync(filePath, "utf8"))))
}

///////////////////////////////////////////////////////////////////////////////
// WORKERS

async function compileCircuit(filePath) {
    console.log("😺 compileCircuit() ...")
    console.time("😺 compileCircuit()")
    const cirDef = await circom(filePath)
    console.timeEnd("😺 compileCircuit()")
    return cirDef
}

function generateSetup(circuit) {
    console.log("😺 generateSetup() ...")
    console.time("😺 generateSetup()")

    const protocol = "groth"
    if (!zkSnark[protocol]) throw new Error("Invalid protocol")

    const setup = zkSnark[protocol].setup(circuit)
    console.timeEnd("😺 generateSetup()")

    return {
        provingKey: setup.vk_proof,
        verificationKey: setup.vk_verifier
    }
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
    console.log("😺 createProof() ...")
    console.time("😺 createProof()")
    const { protocol } = provingKey
    const { proof, publicSignals } = zkSnark[protocol].genProof(provingKey, witness)
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
// MAIN CODE

async function main() {
    console.log("This is going to take some time 😁")

    // COMPILE CIRCUIT
    let circuitSource
    if (fs.existsSync("circuit.json")) {
        circuitSource = deserializeData("./circuit.json")
    }
    else {
        const filePath = path.join(__dirname, "./fp20.circom")
        circuitSource = await compileCircuit(filePath)

        serializeData(circuitSource, "./circuit.json")
    }

    const circuit = new Circuit(circuitSource)

    // GENERATE SETUP
    let provingKey, verificationKey
    if (fs.existsSync("proving_key.json") && fs.existsSync("verification_key.json")) {
        // Stringify twice to ease the work of the bundler
        provingKey = deserializeData("proving_key.json")
        verificationKey = deserializeData("verification_key.json", "utf8")
    }
    else {
        const setup = generateSetup(circuit)
        provingKey = setup.provingKey
        verificationKey = setup.verificationKey

        serializeData(provingKey, "./proving_key.json")
        serializeData(verificationKey, "./verification_key.json")
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
