include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../node_modules/circomlib/circuits/smt/smtprocessor.circom";
include "../node_modules/circomlib/circuits/binsum.circom";

template FranchiseProof(nLevels, nGlobalNullifiers) {

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

    signal         input globalCommitment[nGlobalNullifiers];
    signal private input globalNullifier[nGlobalNullifiers];

    // global nullifier check
    component gnPbkExtract[nGlobalNullifiers];
    component gnCheck[nGlobalNullifiers];
    signal    correctNullifierCount[nGlobalNullifiers];

    for (var n=0;n<nGlobalNullifiers;n+=1) {
        gnPbkExtract[n] = BabyPbk();
        gnPbkExtract[n].in <== globalNullifier[n];

        gnCheck[n] = IsEqual();
        gnCheck[n].in[0] <== gnPbkExtract[n].Ax;
        gnCheck[n].in[1] <== globalCommitment[n];

        if (n == 0) {
            correctNullifierCount[0] <-- gnCheck[n].out;
        } else {
            correctNullifierCount[n] <-- gnCheck[n].out + correctNullifierCount[n-1];
        }
    }

    component gnQuorumCheck = IsEqual()
    gnQuorumCheck.in[0] <== correctNullifierCount[nGlobalNullifiers-1];
    gnQuorumCheck.in[1] <== nGlobalNullifiers;

    signal verify = 1 - gnQuorumCheck.out; 

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
