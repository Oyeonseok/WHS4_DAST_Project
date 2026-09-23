import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import OperatorConsole from "./OperatorConsole";
import "./styles.css";

const preview = new URLSearchParams(window.location.search).get('view') === 'console';

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {preview ? <OperatorConsole /> : <App />}
  </StrictMode>,
);
