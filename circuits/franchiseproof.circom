include "../node_modules/circomlib/circuits/mimc.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";

include "babypbk.circom";

template FranchiseProof(nLevels) {

    signal private input privateKey;
    signal         input votingId;
    signal         input nullifier;

    signal         input censusRoot;
    signal         input censusSiblings[nLevels];
    signal         input censusIdx;

    signal private input voteSigS;
    signal private input voteSigR8x;
    signal private input voteSigR8y;
    signal         input voteValue;

    // -- extract public key -------------------------------------------

    component pbk = BabyPbk();
    pbk.in <== privateKey;

    // -- verify vote signature  ---------------------------------------

    component sigVerification = EdDSAMiMCVerifier();
    sigVerification.enabled <== 1;

    // signer public key (extract from private key)
    sigVerification.Ax <== pbk.Ax;
    sigVerification.Ay <== pbk.Ay;

    // signature (coordinates)
    sigVerification.S <== voteSigS;
    sigVerification.R8x <== voteSigR8x;
    sigVerification.R8y <== voteSigR8y;

    // message
    sigVerification.M <== voteValue;

    // -- verify public key is in census merkle tree ---------------------
    
    component smtCensusInclusion = SMTVerifier(nLevels);
    smtCensusInclusion.enabled <== 1;

    // check for inclusion (0 => VERIFY INCLUSION, 1=>VERIFY EXCLUSION)
    // *old* parameters are not used (only works for EXCLUSION case)
    smtCensusInclusion.fnc <== 0;
    smtSignKeyInclusion.oldKey <== 0;
    smtSignKeyInclusion.oldValue <== 0;
    smtSignKeyInclusion.isOld0 <== 0;

    // root and siblings
    smtCensusInclusion.root <== censusRoot;
    for (var i=0; i<nLevels; i++) {
        smtCensusInclusion.siblings[i] <==  censusSiblings[i];
    }

    // key and value 
    smtSignKeyInclusion.key <== censusIdx;

    component hashAxAy = MultiMiMC7(2, 91);
    hashAxAy.in[0] <== pbk.Ax;
    hashAxAy.in[1] <== pbk.Ay;
    smtCensusInclusion.value <== hashAxAy.out;

    // -- verify nullifier integrity -----------------------------------

    component hashPvkVid = MultiMiMC7(2, 91);
    hashPvkVid.in[0] <== privateKey;
    hashPvkVid.in[1] <== votingId ;
    nullifier === hashPvkVid.out;

}
