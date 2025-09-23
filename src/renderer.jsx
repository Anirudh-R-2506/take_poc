import { createRoot } from 'react-dom/client';
import ProctorDashboard from './renderer/morpheus/ProctorDashboard';
import './index.css';

const App = () => {
    return (
        <div className="app">
            <ProctorDashboard />
        </div>
    );
};

const container = document.getElementById("root");
const root = createRoot(container);
root.render(<App/>);
