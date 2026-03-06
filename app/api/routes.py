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


@router.post('/api/execute')
async def execute_binary(payload: dict = Body(...), request: Request = None):
    """Execute a binary analysis result using the RISC-V simulator.
    
    Request body:
    {
        "rid": "<report_id>",
        "test_input": "<optional stdin input>",
        "args": {"a0": 0, "a1": 0}  # optional ABI registers
    }
    
    Returns execution statistics and benchmarks.
    """
    from app.core.simulator import RiscVSimulator
    
    store = request.app.state.temp_reports
    rid = payload.get("rid")
    test_input = payload.get("test_input", "")
    args = payload.get("args", {})
    
    if not rid or rid not in store:
        raise HTTPException(status_code=404, detail='report not found')
    
    report = store[rid]
    instructions = report.get("instructions", [])
    
    if not instructions:
        raise HTTPException(status_code=400, detail='no instructions to execute')
    
    # Initialize simulator
    sim = RiscVSimulator(memory_size=2 * 1024 * 1024)  # 2MB memory
    
    # Set up argument registers if provided
    if args:
        sim.set_registers_from_abi(
            a0=args.get("a0", 0),
            a1=args.get("a1", 0),
            a2=args.get("a2", 0),
            a3=args.get("a3", 0)
        )
    
    # Set input if provided
    if test_input:
        sim.set_input(test_input)
    
    # Run simulation (max 100k instructions to prevent infinite loops)
    exec_stats = sim.run(instructions, max_iterations=100000)
    
    # Store execution results in report for later retrieval
    store[rid]["execution_results"] = exec_stats
    
    return {
        "rid": rid,
        "status": "success",
        "execution": exec_stats
    }


@router.post('/api/benchmark')
async def benchmark_comparison(payload: dict = Body(...), request: Request = None):
    """Compare execution metrics between two binary versions.
    
    Request body:
    {
        "rid1": "<report_id_v1>",
        "rid2": "<report_id_v2>",
        "test_input": "<optional stdin input>"
    }
    
    Returns performance delta and comparison metrics.
    """
    from app.core.simulator import RiscVSimulator
    
    store = request.app.state.temp_reports
    rid1 = payload.get("rid1")
    rid2 = payload.get("rid2")
    test_input = payload.get("test_input", "")
    
    if not rid1 or rid1 not in store or not rid2 or rid2 not in store:
        raise HTTPException(status_code=404, detail='one or both reports not found')
    
    report1 = store[rid1]
    report2 = store[rid2]
    
    # Get or run execution results
    exec1 = report1.get("execution_results")
    if not exec1:
        sim1 = RiscVSimulator()
        sim1.set_input(test_input)
        exec1 = sim1.run(report1.get("instructions", []), max_iterations=100000)
        report1["execution_results"] = exec1
    
    exec2 = report2.get("execution_results")
    if not exec2:
        sim2 = RiscVSimulator()
        sim2.set_input(test_input)
        exec2 = sim2.run(report2.get("instructions", []), max_iterations=100000)
        report2["execution_results"] = exec2
    
    # Calculate deltas
    instr_delta = exec2["instructions_executed"] - exec1["instructions_executed"]
    instr_pct_delta = (instr_delta / max(1, exec1["instructions_executed"])) * 100
    
    cycles_delta = exec2["cycles_estimate"] - exec1["cycles_estimate"]
    cycles_pct_delta = (cycles_delta / max(1, exec1["cycles_estimate"])) * 100
    
    ipc_delta = exec2["ipc_estimate"] - exec1["ipc_estimate"]
    
    # Memory access comparison
    mem_delta = exec2["memory_accesses"]["total"] - exec1["memory_accesses"]["total"]
    mem_pct_delta = (mem_delta / max(1, exec1["memory_accesses"]["total"])) * 100
    
    comparison = {
        "v1_id": rid1,
        "v2_id": rid2,
        "instructions": {
            "v1": exec1["instructions_executed"],
            "v2": exec2["instructions_executed"],
            "delta": instr_delta,
            "delta_pct": instr_pct_delta,
            "status": "improved" if instr_delta < 0 else "regressed" if instr_delta > 0 else "same"
        },
        "cycles": {
            "v1": exec1["cycles_estimate"],
            "v2": exec2["cycles_estimate"],
            "delta": cycles_delta,
            "delta_pct": cycles_pct_delta,
            "status": "improved" if cycles_delta < 0 else "regressed" if cycles_delta > 0 else "same"
        },
        "ipc": {
            "v1": round(exec1["ipc_estimate"], 3),
            "v2": round(exec2["ipc_estimate"], 3),
            "delta": round(ipc_delta, 3)
        },
        "memory_accesses": {
            "v1": exec1["memory_accesses"]["total"],
            "v2": exec2["memory_accesses"]["total"],
            "delta": mem_delta,
            "delta_pct": mem_pct_delta,
            "status": "improved" if mem_delta < 0 else "regressed" if mem_delta > 0 else "same"
        },
        "branches": {
            "v1": exec1["branches_total"],
            "v2": exec2["branches_total"],
            "delta": exec2["branches_total"] - exec1["branches_total"]
        },
        "loops_detected": {
            "v1": len(exec1.get("loops_detected", [])),
            "v2": len(exec2.get("loops_detected", []))
        },
        "stack_usage": {
            "v1": exec1.get("stack_usage", "N/A"),
            "v2": exec2.get("stack_usage", "N/A")
        },
        "heap_usage": {
            "v1": exec1.get("heap_usage", "N/A"),
            "v2": exec2.get("heap_usage", "N/A")
        }
    }
    
    return {
        "status": "success",
        "comparison": comparison
    }


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