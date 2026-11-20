
"""FastAPI application entry point."""

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import DBAPIError, OperationalError

from config.settings import Settings, get_settings
from database.connection import init_db

from .logging import configure_logging

from .routes.system import router as system_router
from .routes.auth import router as auth_router
from .routes.biometrics import router as biometrics_router
from .routes.oauth import router as oauth_router
from .routes.chat import router as chat_router
from .routes.documents import router as documents_router
from .routes.admin import router as admin_router
from .routes.rag import router as rag_router


API_VERSION = "0.1.0"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the application using the shared project settings."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.debug)

    # Initialize database
    init_db()

    application = FastAPI(
        title=resolved_settings.app_name,
        version=API_VERSION,
        description="Agentic RAG API",
    )

    application.state.environment = resolved_settings.app_env

    # Frontend build directory
    frontend_dir = (
        Path(__file__).resolve().parent.parent
        / "frontend"
        / "dist"
    )

    index_file = frontend_dir / "index.html"

    # Serve React frontend at root
    # Register this BEFORE system_router to avoid root route conflicts.
    if index_file.exists():

        @application.get("/", include_in_schema=False)
        async def serve_frontend():
            return FileResponse(index_file)

    # Health check for Render
    @application.get("/health")
    @application.head("/health")
    async def health_check():
        return {"status": "healthy"}

    # CORS configuration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Database exception handlers
    @application.exception_handler(OperationalError)
    @application.exception_handler(DBAPIError)
    async def database_exception_handler(
        request: Request,
        exc: Exception,
    ):
        logger = logging.getLogger("uvicorn.error")
        logger.error(
            f"Database unavailable: {exc}",
            exc_info=True,
        )

        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "Database service is currently unavailable. "
                    "Please try again shortly."
                )
            },
        )

    # General exception handler
    @application.exception_handler(Exception)
    async def global_exception_handler(
        request: Request,
        exc: Exception,
    ):
        logger = logging.getLogger("uvicorn.error")
        logger.error(
            f"Unhandled exception: {exc}",
            exc_info=True,
        )

        if application.state.environment == "production":
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )

        return JSONResponse(
            status_code=500,
            content={"detail": str(exc)},
        )

    # Register API routes
    application.include_router(system_router)

    application.include_router(auth_router)
    application.include_router(auth_router, prefix="/api")

    application.include_router(biometrics_router)
    application.include_router(oauth_router)
    application.include_router(chat_router)
    application.include_router(documents_router)

    application.include_router(admin_router)
    application.include_router(admin_router, prefix="/api")

    application.include_router(rag_router)

    # Serve React static assets and SPA routes.
    # Keep this AFTER all API routers.
    if index_file.exists():

        @application.get("/{full_path:path}", include_in_schema=False)
        async def serve_frontend_routes(full_path: str):
            requested_file = (
                frontend_dir / full_path
            ).resolve()

            frontend_root = frontend_dir.resolve()

            # Serve existing frontend files safely
            if (
                requested_file.is_file()
                and frontend_root in requested_file.parents
            ):
                return FileResponse(requested_file)

            # Do not return React HTML for unknown API routes
            if (
                full_path == "api"
                or full_path.startswith("api/")
                or full_path == "health"
                or full_path.startswith("docs")
                or full_path == "openapi.json"
            ):
                return JSONResponse(
                    status_code=404,
                    content={"detail": "Not found"},
                )

            # React Router fallback
            return FileResponse(index_file)

    return application


app = create_app()
