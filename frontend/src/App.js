import React, { useState, useEffect } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const apiBase = "http://127.0.0.1:8000";

  const scanUrl = async () => {
    setResult({ status: "loading" });
    try {
      const res = await fetch(`${apiBase}/scan-url`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      setResult(data);
      fetchHistory();
    } catch (e) {
      setResult({ status: "error", error: e.toString() });
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${apiBase}/history?limit=20`);
      const data = await res.json();
      setHistory(data.results || []);
    } catch (e) {
      // ignore
    }
  };

  useEffect(() => { fetchHistory(); }, []);

  return (
    <div style={{ maxWidth: 900, margin: "32px auto", fontFamily: "Inter, Arial" }}>
      <h1>AI Phishing Detection — Dashboard</h1>

      <div style={{ marginBottom: 16 }}>
        <input
          placeholder="Enter URL to scan (e.g. https://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ width: "70%", padding: 8, marginRight: 8 }}
        />
        <button onClick={scanUrl} style={{ padding: "8px 16px" }}>Scan</button>
      </div>

      <div style={{ marginBottom: 24 }}>
        <h3>Latest Scan Result</h3>
        <pre style={{ background: "#f5f5f5", padding: 12 }}>
          {result ? JSON.stringify(result, null, 2) : "No scan yet"}
        </pre>
      </div>

      <div>
        <h3>Scan History (last 20)</h3>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ borderBottom: "1px solid #ddd", padding: 8 }}>ID</th>
              <th style={{ borderBottom: "1px solid #ddd", padding: 8 }}>URL</th>
              <th style={{ borderBottom: "1px solid #ddd", padding: 8 }}>Prediction</th>
              <th style={{ borderBottom: "1px solid #ddd", padding: 8 }}>Risk</th>
              <th style={{ borderBottom: "1px solid #ddd", padding: 8 }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {history.map(h => (
              <tr key={h.id}>
                <td style={{ padding: 8, borderBottom: "1px solid #eee" }}>{h.id}</td>
                <td style={{ padding: 8, borderBottom: "1px solid #eee" }}>{h.url}</td>
                <td style={{ padding: 8, borderBottom: "1px solid #eee" }}>{h.prediction}</td>
                <td style={{ padding: 8, borderBottom: "1px solid #eee" }}>{h.risk_score}</td>
                <td style={{ padding: 8, borderBottom: "1px solid #eee" }}>{new Date(h.timestamp).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;
