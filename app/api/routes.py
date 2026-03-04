from fastapi import APIRouter, UploadFile, File, HTTPException, Request, Body
import os
from app.sandbox.validator import validate_elf
from app.core.pipeline import analyze
from fastapi.responses import FileResponse
from app.api.validators import validate_report_schema

router = APIRouter()


async def _process_file_bytes(file_bytes: bytes, request: Request):
    validate_elf(file_bytes)
    report = analyze(file_bytes)
    result = report.to_dict()
    # validate response schema before returning to clients
    try:
        validate_report_schema(result)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # store temporarily and return an id for route-based retrieval
    import uuid
    rid = uuid.uuid4().hex
    # store on app state; report will be removed when fetched
    request.app.state.temp_reports[rid] = result
    return {"id": rid, "url": f"/result/{rid}"}


@router.post("/api/analyze")
async def analyze_binary(file: UploadFile = File(...), request: Request = None):
    file_bytes = await file.read()
    return await _process_file_bytes(file_bytes, request)


@router.post("/analyze")
async def analyze_binary_legacy(file: UploadFile = File(...), request: Request = None):
    # legacy compatibility route forwards to /api/analyze behavior
    file_bytes = await file.read()
    return await _process_file_bytes(file_bytes, request)


@router.get('/result/{rid}')
async def result_page(rid: str):
    # serve the result HTML page (no client-side session storage required)
    return FileResponse('app/static/result.html')


@router.get('/api/result/{rid}')
async def get_result(rid: str, request: Request):
    # Return the stored report for `rid` and remove it so reload clears it.
    store = request.app.state.temp_reports
    report = store.get(rid)
    if report is None:
        raise HTTPException(status_code=404, detail='report not found or expired')
    # Optionally remove report after first fetch. Controlled by env var
    # ONE_TIME_FETCH (default: '0' => keep report). Set to '1' to delete after fetch.
    one_time = os.getenv('ONE_TIME_FETCH', '0')
    if one_time == '1':
        try:
            del store[rid]
        except Exception:
            pass
    return report


@router.post('/api/debug/store_result')
async def store_result(payload: dict = Body(...), request: Request = None):
    """Debug helper: store a provided report JSON and return a temporary id

    Use this to inject a test report and then open `/result/{id}` in the browser.
    """
    # validate report shape before storing
    try:
        validate_report_schema(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    import uuid
    rid = uuid.uuid4().hex
    request.app.state.temp_reports[rid] = payload
    return {"id": rid, "url": f"/result/{rid}"}


@router.get("/")
async def get_html():
    return FileResponse("app/static/gpt.html")


@router.get('/api/result/{rid}/export')
async def export_result_html(rid: str, request: Request):
    """Export a complete result as a self-contained HTML file with embedded JSON."""
    store = request.app.state.temp_reports
    report = store.get(rid)
    if report is None:
        raise HTTPException(status_code=404, detail='report not found or expired')

    import json
    json_str = json.dumps(report)

    # Build a minimal standalone HTML page with embedded JSON
    html_content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>RISC-V Binary Intelligence — Report Export</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{{background:#f3f6fb;color:#222}}
    .stat-value{{font-size:1.3rem;font-weight:600}}
    .small-muted{{color:#6c757d;font-size:0.85rem}}
    .summary-list{{margin:0;padding-left:1.1rem}}
    pre{{max-height:400px;overflow:auto;background:#0d1117;color:#c9d1d9;padding:12px;border-radius:6px}}
  </style>
</head>
<body>
  <nav class="navbar navbar-light bg-white border-bottom mb-3">
    <div class="container">
      <span class="navbar-brand">RISC-V Binary Intelligence — Offline Report</span>
      <span class="badge bg-info">Self-contained export</span>
    </div>
  </nav>
  <main class="container">
    <div class="row g-3">
      <div class="col-12">
        <h4>Report Summary</h4>
        <div class="alert alert-info">This is a standalone HTML file with embedded report data. No internet connection required.</div>
      </div>
    </div>
    <div class="row g-3">
      <div class="col-lg-8">
        <div class="card">
          <div class="card-body">
            <h5>Summary</h5>
            <div id="summary" class="small-muted"></div>
            <hr/>
            <h5>Pseudocode</h5>
            <div id="pseudocode" style="font-family: monospace; font-size: 0.85rem;"></div>
            <hr/>
            <h5>Recommendations</h5>
            <div id="recommendations"></div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card">
          <div class="card-body">
            <h6>Quick Stats</h6>
            <div id="stats" class="small-muted"></div>
          </div>
        </div>
      </div>
    </div>
    <div class="row g-3 mt-3">
      <div class="col-12">
        <div class="card">
          <div class="card-body">
            <h6>Raw JSON Data</h6>
            <pre id="json"></pre>
          </div>
        </div>
      </div>
    </div>
  </main>

  <script>
    const data = JSON.parse({json.dumps(json_str)});
    
    // Populate summary
    const summ = data.instruction_summary || [];
    document.getElementById('summary').innerHTML = summ.length ? 
      `<ul class="summary-list mb-0">${{summ.map(x => `<li>${{x}}</li>`).join('')}}</ul>` : 
      '<div class="text-muted">No summary.</div>';
    
    // Populate pseudocode
    const pseudo = data.pseudocode || [];
    document.getElementById('pseudocode').innerHTML = pseudo.length ? 
      pseudo.map(p => `<div>${{p}}</div>`).join('') : 
      '<div class="text-muted">No pseudocode.</div>';
    
    // Populate recommendations
    const recs = data.recommendations || [];
    document.getElementById('recommendations').innerHTML = recs.length ? 
      `<ul>${{recs.map(r => `<li>${{r}}</li>`).join('')}}</ul>` : 
      '<div class="text-muted">No recommendations.</div>';
    
    // Populate stats
    const stats = data.instruction_stats || {{}};
    const h = data.heuristics || {{}};
    document.getElementById('stats').innerHTML = `
      <div>Total: ${{stats.total ?? '-'}}</div>
      <div>Memory intensity: ${{(h.memory_intensity ?? '-')}}</div>
      <div>Branch density: ${{(h.branch_density ?? '-')}}</div>
      <div>Risk score: ${{(h.risk_score ?? '-')}}</div>
    `;
    
    // Raw JSON
    document.getElementById('json').textContent = JSON.stringify(data, null, 2);
  </script>
</body>
</html>"""
    
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content, headers={
        "Content-Disposition": f"attachment; filename=report-{rid[:8]}.html"
    })