from fastapi import FastAPI
from app.api.routes import router
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.include_router(router)

# Serve static assets (frontend) at /static
app.mount('/static', StaticFiles(directory='app/static'), name='static')

# Temporary in-memory storage for analysis reports keyed by short id.
# Reports are removed after first retrieval so reloads will clear them.
app.state.temp_reports = {}