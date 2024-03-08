import logo from './logo.svg';
import './App.css';
import { wrap } from 'comlink';


function App() {
    const worker = new Worker(new URL('./halo2-worker', import.meta.url), {
        name: 'halo2-worker',
        type: 'module',
    });
    const workerApi = wrap<import('./halo2-worker').Halo2Worker>(worker);

    async function prove() {
        await workerApi.prove();
    }

    async function verify() {
        await workerApi.verify();
    }

    return (
        <div className="App">
        <header className="App-header">
            <img src={logo} className="App-logo" alt="logo" />
            <p>
            Benchmark test for authdecode in browser
            </p>
            <button onClick={prove}>prove</button>
            <button onClick={verify}>verify</button>
        </header>
        </div>
    );
}

export default App;
