"""Backend-local entrypoint for running the Flask app from `backend/`."""

import os
import sys
from pathlib import Path


def _bootstrap_backend_venv() -> None:
    """Re-run this file with the backend virtualenv when Flask packages are missing."""
    if os.environ.get("WEBSHIELD_VENV_BOOTSTRAPPED") == "1":
        return

    backend_root = Path(__file__).resolve().parent
    venv_root = backend_root / ".venv"
    venv_python = venv_root / "bin" / "python"
    if not venv_python.exists():
        return

    if Path(sys.prefix).resolve() == venv_root.resolve():
        return

    try:
        import click  # noqa: F401
        import flask  # noqa: F401
    except ModuleNotFoundError:
        env = os.environ.copy()
        env["WEBSHIELD_VENV_BOOTSTRAPPED"] = "1"
        os.execve(
            str(venv_python),
            [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]],
            env,
        )


_bootstrap_backend_venv()

from app import create_app

app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
