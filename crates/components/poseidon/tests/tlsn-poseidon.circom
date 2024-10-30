pragma circom 2.1.5;

include "poseidon.circom";

template PoseidonProof(NUMBER_OF_INPUTS) {
    // The circuit takes two inputs: the pre-images and an additional scope parameter.
    signal input preimages[NUMBER_OF_INPUTS];
    signal input scope;

    assert (NUMBER_OF_INPUTS >= 1);
    assert (NUMBER_OF_INPUTS <= 16);

    // It applies the Poseidon hash function to the pre-image to produce a hash digest.
    signal output digest;
    digest <== Poseidon(NUMBER_OF_INPUTS)(preimages);

    // Dummy constraint to prevent compiler from optimizing it.
    signal dummySquare <== scope * scope;
}

 component main = PoseidonProof(2);
