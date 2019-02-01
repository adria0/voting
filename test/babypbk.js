const chai = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const compiler = require("circom");
const createBlakeHash = require("blake-hash");
const bigInt = require("snarkjs").bigInt;

const babyJub = require("circomlib").babyjub;
const assert = chai.assert;

describe("BabyPbk", function () {
    this.timeout(100000);

    it("Extract public key from private key", async () => {    

        const rawpvk = Buffer.from("0001020304050607080900010203040506070809000102030405060708090021", "hex");
        const pvk    = createBlakeHash("blake512").update(rawpvk).digest().slice(0,32);
        const S      = bigInt.leBuff2int(pvk).shr(3);
        const A      = babyJub.mulPointEscalar(babyJub.Base8, S);

        const cirDef = await compiler(path.join(__dirname, "circuits", "testbabypbk.circom"));
        circuit      = new snarkjs.Circuit(cirDef);

        const input = {
            in : S,
            Ax : A[0],
            Ay : A[1]
        }

        const w = circuit.calculateWitness(input);
        assert(circuit.checkWitness(w));
    })

})