# Authdecode Benchmarking in Browser
## Objective
To benchmark the performance of halo2 authdecode prover wasm in browser

## Implementation
The implementation of wasm prover and verifier code, together with the react app are heavily adapted from and influenced by the following implementations / references
- [halo2 wasm guide](https://zcash.github.io/halo2/user/wasm-port.html)
- [zordle — zk wordle using halo2 prover. verifier in browser](https://github.com/nalinbhardwaj/zordle)
- [tlsn-js](https://github.com/tlsnotary/tlsn-js/tree/main)
- [zkemail halo2 wasm benchmark](https://github.com/zkemail/halo2-benchmark-wasm/tree/main)

## Instruction
0. Make sure you can compile wasm successfully by checking if the following command succeeds without errors at the root of this crate: `cargo clippy --target wasm32-unknown-unknown` (if failed, try updating rust)
1. Run `cd browser-benchmark; npm install`
2. Run `npm run build:wasm`
3. Run `npm run build`
4. Run `npm run serve`
5. Open browser at http://localhost:3000 — use incognito to prevent browser caching
6. Follow the instruction on the webpage

## Performance Factor
- Plaintext payload size (`PLAINTEXT_SIZE`) in [wasm.rs](../src/wasm.rs)
- Number of browser threads (`NUM_OF_THREAD`) in [halo2-worker.ts](./src/halo2-worker.ts)

## Miscellaneous
- One can also run `npm start` to start the react app, but `npm run build` can produce an optimised production build for better performance benchmarking
- [serve.json](./serve.json) has to be used to allow multithreading in browser to work ([ref](https://github.com/RReverser/wasm-bindgen-rayon?tab=readme-ov-file#setting-up))
- Usage of `std::time` needs to be replaced or removed in rust codes, else browser will complain `time not implemented on this platform`
- In [package.json](./package.json), `"ignorePatterns": ["wasm"]` needs to be defined to avoid eslint error on js files compiled from wasm
- [config](./config/) and [scripts](./scripts/) are copied from [zordle](https://github.com/nalinbhardwaj/zordle) — they mainly handle bundling and building of the react app using webpack
- To compile authdecode without wasm, one can run cargo with a your machine target, e.g. `cargo clippy --target aarch64-apple-darwin`
- For VSCode rust-analyzer to work with wasm, insert the following in `.vscode/settings.json`: `"rust-analyzer.cargo.target": "wasm32-unknown-unknown"`
