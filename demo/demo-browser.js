import "babel-polyfill"
const { FPVoter, FPCensus } = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs")
const { bigInt } = zkSnark

// Stored as an all-string JSON
const serializedCircuit = require("./circuit.json")
const serializedProvingKey = require("./proving_key.json")
const serializedVerificationKey = require("./verification_key.json")

///////////////////////////////////////////////////////////////////////////////
// BIG INT HELPERS

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

function deserializeData(payload) {
    return parseBigInts(JSON.parse(payload))
}

///////////////////////////////////////////////////////////////////////////////
// WORKERS

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
    console.log("This is going to take some time 😁 ")

    // COMPILE CIRCUIT
    let circuitSource = deserializeData(serializedCircuit)

    const circuit = new zkSnark.Circuit(circuitSource)

    // GENERATE SETUP
    let provingKey, verificationKey
    provingKey = deserializeData(serializedProvingKey)
    verificationKey = deserializeData(serializedVerificationKey)

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
