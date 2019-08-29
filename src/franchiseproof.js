const bigInt = require("../node_modules/snarkjs").bigInt;
const { assert } = require("chai");
const createBlakeHash = require("blake-hash");
const { babyJub, eddsa, smt, poseidon } = require("../node_modules/circomlib");

const hash = poseidon.createHash(6, 8, 57);

function genKeyPair(rawpvkHex) {
    const rawpvk = Buffer.from(rawpvkHex, "hex");
    const rawpvkHash = eddsa.pruneBuffer(createBlakeHash("blake512").update(rawpvk).digest().slice(0, 32));
    const pvk = bigInt.leBuff2int(rawpvkHash).shr(3);
    const A = babyJub.mulPointEscalar(babyJub.Base8, pvk);
    return { rawpvk , pvk , pbk : { x: A[0], y: A[1] } }
}

class FPCensus {
    constructor(levels, globalCommitmentData) {
        this.levels = levels;
        this.tree = null;
        this.key = genKeyPair(globalCommitmentData)
    }
    async add(idx, publicKeyHash) {
        if (this.tree === null) {
            this.tree = await smt.newMemEmptyTrie();
        }
        await this.tree.insert(idx, publicKeyHash);
    }
    async proofOfInclusion(idx) {
        const res = await this.tree.find(idx);
        assert(res.found);
        let siblings = res.siblings;
        while (siblings.length < this.levels) siblings.push(bigInt(0));
        return {
            root: this.tree.root,
            siblings: siblings,
            globalCommitment : this.key.pbk.x
        };
    }
}

class FPVoter {
    constructor(idx, rawpvkHex) {
        this.idx = idx;
        this.key = genKeyPair(rawpvkHex);
    }

    async getPublicKeyHash() {
        return hash([this.key.pbk.x, this.key.pbk.y]);
    }

    async getInput(votingId, voteValue, proofOfInclusion) {

        const nullifier = hash([this.key.pvk, votingId]);
        const signature = eddsa.signPoseidon(this.key.rawpvk, voteValue);

        return {
            privateKey : this.key.pvk,
            votingId,
            nullifier,
            censusRoot: proofOfInclusion.root,
            censusSiblings: proofOfInclusion.siblings,
            censusIdx: this.idx,
            voteSigS: signature.S,
            voteSigR8x: signature.R8[0],
            voteSigR8y: signature.R8[1],
            voteValue,
            globalCommitment : proofOfInclusion.globalCommitment,
            globalNullifier  : 0,
        }
    }
}

module.exports = {
    FPCensus,
    FPVoter
}