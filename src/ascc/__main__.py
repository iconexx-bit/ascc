"""Канонический вход: python -m ascc.

Entry-point `ascc` из [project.scripts] резолвится через PATH и может
указывать на stale/глобальный бинарь. Этот модуль исключает PATH.
"""

from ascc.cli import app

if __name__ == "__main__":
    app()
