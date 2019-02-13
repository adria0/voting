import "babel-polyfill"
const { FPVoter, FPCensus } = require("../src/franchiseproof.js")
const zkSnark = require("snarkjs")
const { bigInt, Circuit } = zkSnark
import { toByteArray } from 'base64-js'
import { Lzp3 } from '@faithlife/compressjs'

// Stored as an all-string JSON
const serializedCircuit = require("./circuit.lzp3.json")
const serializedProvingKey = require("./proving-key.lzp3.json")
const serializedVerificationKey = require("./verification-key.lzp3.json")

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

const utf8ArrayToStr = (function () {
    var charCache = new Array(128);  // Preallocate the cache for the common single byte chars
    var charFromCodePt = String.fromCodePoint || String.fromCharCode;
    var result = [];

    return function (array) {
        var codePt, byte1;
        var buffLen = array.length;

        result.length = 0;

        for (var i = 0; i < buffLen;) {
            byte1 = array[i++];

            if (byte1 <= 0x7F) {
                codePt = byte1;
            } else if (byte1 <= 0xDF) {
                codePt = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F);
            } else if (byte1 <= 0xEF) {
                codePt = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else if (String.fromCodePoint) {
                codePt = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else {
                codePt = 63;    // Cannot convert four byte code points, so use "?" instead
                i += 3;
            }

            result.push(charCache[codePt] || (charCache[codePt] = charFromCodePt(codePt)));
        }

        return result.join('');
    };
})();

// TODO: REMOVE
function largeuint8ArrToString(uint8arr, callback) {
    var bb = new Blob([uint8arr]);
    var f = new FileReader();
    f.onload = function (e) {
        callback(e.target.result);
    };

    f.readAsText(bb);
}

function deserializeData(serializedPayload) {
    if (!serializedPayload) throw new Error("Empty payload")

    const uncompressedArray = Lzp3.decompressFile(toByteArray(serializedPayload))

    let k = "deserialize-1-" + Math.random()
    console.time(k)
    const rawString = utf8ArrayToStr(uncompressedArray)
    console.timeEnd(k)


    // TODO: REMOVE

    k = "deserialize-2-" + Math.random()
    console.time(k)
    largeuint8ArrToString(new Uint8Array(uncompressedArray), data => {
        console.timeEnd(k)
    })

    return parseBigInts(JSON.parse(rawString))
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

    const circuit = new Circuit(circuitSource)

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
