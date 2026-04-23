function scoreIPStream(ip) {
  const source = new EventSource(`/api/stream/${encodeURIComponent(ip)}`);

  source.addEventListener("stage", e => {
    const { step } = JSON.parse(e.data);
    resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><span>${escHtml(step)}</span></div>`;
  });

  source.addEventListener("result", e => {
    const data = JSON.parse(e.data);
    renderResult(data);
    addAuditEntry(data);
    updateStats(data.riskLevel);
  });

  source.addEventListener("error", () => {
    showError("Stream failed. Please retry.");
    source.close();
    setLoading(false);
  });

  source.addEventListener("done", () => {
    source.close();
    setLoading(false);
  });
}