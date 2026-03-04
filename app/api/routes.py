from fastapi import APIRouter, UploadFile, File, HTTPException, Request
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
    # remove after first fetch
    del store[rid]
    return report


@router.get("/")
async def get_html():
    return FileResponse("app/static/gpt.html")