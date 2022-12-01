import uvicorn
from .settings import settings


uvicorn.run(
    'wrokshop.main:app',
    host=settings.server_host,
    port=settings.server_port,
    reload=True
)
