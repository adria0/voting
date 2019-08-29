include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";

template FranchiseProof(nLevels) {

    signal         input censusRoot;
    signal private input censusSiblings[nLevels];
    signal private input censusIdx;

    signal private input voteSigS;
    signal private input voteSigR8x;
    signal private input voteSigR8y;

    signal         input voteValue;

    signal private input privateKey;
    
    signal         input votingId;
    signal         input nullifier;

    signal         input globalCommitment;
    signal private input globalNullifier;

    // global nullifier check
    component gnPbkExtract = BabyPbk();
    gnPbkExtract.in <== globalNullifier;

    component gnCheck = IsEqual()
    gnCheck.in[0] <== gnPbkExtract.Ax;
    gnCheck.in[1] <== globalCommitment;

    signal verify = 1 - gnCheck.out; 

    // -- extract public key -------------------------------------------
    component pbk = BabyPbk();
    pbk.in <== privateKey;

    // -- verify vote signature  ---------------------------------------
    component sigVerification = EdDSAPoseidonVerifier();
    sigVerification.enabled <== verify;

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
    smtCensusInclusion.enabled <== verify;

    // check for inclusion (0 => VERIFY INCLUSION, 1=>VERIFY EXCLUSION)
    smtCensusInclusion.fnc <== 0;

    // *old* parameters are not used (only works for EXCLUSION case)
    smtCensusInclusion.oldKey <== 0;
    smtCensusInclusion.oldValue <== 0;
    smtCensusInclusion.isOld0 <== 0;

    // root and siblings
    smtCensusInclusion.root <== censusRoot;
    for (var i=0; i<nLevels; i++) {
        smtCensusInclusion.siblings[i] <==  censusSiblings[i];
    }

    // key and value 
    smtCensusInclusion.key <== censusIdx;

    component hashAxAy = Poseidon(2,6,8,57);
    hashAxAy.inputs[0] <== pbk.Ax;
    hashAxAy.inputs[1] <== pbk.Ay;
    smtCensusInclusion.value <== hashAxAy.out;

    // -- verify nullifier integrity -----------------------------------
    component hashPvkVid = Poseidon(2,6,8,57);
    hashPvkVid.inputs[0] <== privateKey;
    hashPvkVid.inputs[1] <== votingId ;
    
    component nullifierCheck = ForceEqualIfEnabled();
    nullifierCheck.enabled <== verify;
    nullifierCheck.in[0] <== nullifier;
    nullifierCheck.in[1] <== hashPvkVid.out;

}
