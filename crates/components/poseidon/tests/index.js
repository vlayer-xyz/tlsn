import { poseidon16 } from 'poseidon-lite/poseidon16'


//// https://github.com/iden3/circomlibjs/blob/bfa4ce13661e747e82ed74d1114659e354c1b60b/test/poseidon.js#L53
const hash = poseidon16([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
console.log("poseidon16: ", hash);
