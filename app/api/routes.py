from fastapi import APIRouter, UploadFile, File
from app.sandbox.validator import validate_elf
from app.core.pipeline import analyze
from fastapi.responses import FileResponse

router = APIRouter()


@router.post("/analyze")
async def analyze_binary(file: UploadFile = File(...)):
    file_bytes = await file.read()

    validate_elf(file_bytes)

    report = analyze(file_bytes)

    return report.to_dict()

@router.get("/")
async def get_html():
    return FileResponse("app/static/index.html")