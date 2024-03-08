import { expose } from 'comlink';

const NUM_OF_THREAD = 1;

async function prove() {
    console.log('Prove called');
    const {
        default: init,
        initThreadPool,
        prove,
        init_panic_hook
    } = await import("./wasm/authdecode.js");

    await init();
    await initThreadPool(NUM_OF_THREAD);
    init_panic_hook();
    
    console.time("Proving starts");
    await prove();
    console.timeEnd("Proving ends");
}

async function verify() {
    console.log('Verify called');
    const {
        default: init,
        initThreadPool,
        verify,
        init_panic_hook
    } = await import("./wasm/authdecode.js");

    await init();
    await initThreadPool(NUM_OF_THREAD);
    init_panic_hook();
    
    console.time("Proving + verifying start");
    await verify();
    console.timeEnd("Proving + verifying ends");
}

const exports = {
    prove,
    verify
};
export type Halo2Worker = typeof exports;

expose(exports);
