"""Run the JWKS server: ``python -m app`` from the project directory."""

from __future__ import annotations

import logging

import uvicorn

from app.config import Settings
from app.main import create_app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = Settings()
    application = create_app(settings)
    uvicorn.run(application, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
