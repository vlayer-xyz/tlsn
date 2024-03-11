import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';


function App() {
    const worker = new Worker(new URL('./halo2-worker', import.meta.url), {
        name: 'halo2-worker',
        type: 'module',
    });
    const workerApi = wrap<import('./halo2-worker').Halo2Worker>(worker);

    function prove() {
        workerApi.prover();
    }

    function verify() {
        workerApi.verifier();
    }

    async function setup() {
        await workerApi.setup();
    }
    // one time setup of the panic hook, thread pool
    setup();

    return (
        <div className="App">
        <header className="App-header">
            <img src={logo} className="App-logo" alt="logo" />
            <h3>
            Benchmarking Test for Authdecode in Browser 
            </h3>
            <p style={{ fontSize: '20px' }}>Open console log (where latency will be printed), then press either button below</p>
            <div style={{}}>
                <button className="big-button" style={{ marginRight: '50px' }} onClick={prove}>Prove</button>
                <button className="big-button" onClick={verify}>Prove + Verify</button>
            </div>
        </header>
        </div>
    );
}

export default App;
