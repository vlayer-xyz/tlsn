import { expose } from 'comlink';
import init, {
    initThreadPool,
    init_panic_hook,
    prove,
    verify,
} from "./wasm/authdecode.js";


const NUM_OF_THREAD = 4;

export const setup = async () => {
    console.log("Wasm setup called");
    await init();
    init_panic_hook();
    await initThreadPool(NUM_OF_THREAD);
}

export const prover = () =>  {
    console.log('Prove called');
    console.time("Proving latency");
    prove();
    console.timeEnd("Proving latency");
};

export const verifier = () => {
    console.log('Verify called');
    console.time("Proving + verifying latency");
    verify();
    console.timeEnd("Proving + verifying latency");
};

const exports = {
    setup,
    prover,
    verifier,
};
export type Halo2Worker = typeof exports;

expose(exports);
