const bigInt = require("snarkjs").bigInt;
const chai = require("chai");
const createBlakeHash = require("blake-hash");
const mimc7 = require("circomlib").mimc7;
const smt = require("circomlib").smt;
const babyJub = require("circomlib").babyjub;
const eddsa = require("circomlib").eddsa;
const assert = chai.assert;

class fpcensus {
    constructor(levels) {
        this.levels = levels;
        this.tree = null;
    }
    async add(idx,publicKeyHash) {
        if (this.tree === null) {
            this.tree = await smt.newMemEmptyTrie();
        }
        await this.tree.insert(idx,publicKeyHash);
    }
    async proofOfInclusion(idx) {
        const res = await this.tree.find(idx);
        assert(res.found);
        let siblings = res.siblings;
        while (siblings.length<this.levels) siblings.push(bigInt(0));
        return { root: this.tree.root, siblings: siblings };
    }
}

class fpvoter {
    constructor(idx,rawpvk) {
        this.idx = idx;
        this.rawpvk = Buffer.from(rawpvk,"hex");
    }
    async _derivedPvk() {
        const pvk = eddsa.pruneBuffer(createBlakeHash("blake512").update(this.rawpvk).digest().slice(0,32));
        return bigInt.leBuff2int(pvk).shr(3);
    }

    async getPublicKeyHash() {
        const A = babyJub.mulPointEscalar(babyJub.Base8, await this._derivedPvk());
        return mimc7.multiHash([A[0],A[1]]);
    }

    async getInput(votingId,voteValue, proofOfInclusion) {

        const privateKey = await this._derivedPvk()
        const nullifier = mimc7.multiHash([privateKey,votingId]);
        const signature = eddsa.signMiMC(this.rawpvk, voteValue);
        
        return {
            privateKey     : privateKey,
            votingId       : votingId,
            nullifier      : nullifier,
            censusRoot     : proofOfInclusion.root,
            censusSiblings : proofOfInclusion.siblings,
            censusIdx      : this.idx,
            voteSigS       : signature.S,
            voteSigR8x     : signature.R8[0],
            voteSigR8y     : signature.R8[1],
            voteValue      : voteValue
        }
    }
}

module.exports = {
    fpcensus,
    fpvoter
}
