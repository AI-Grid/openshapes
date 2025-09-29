"""Utility helpers for the OpenShapes manager application."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CONFIG_ROOT = Path(__file__).resolve().parent.parent / "config"
DEFAULT_CONFIG_FILE = CONFIG_ROOT / "app.ini"


class ConfigLoader:
    """Simple configuration loader that works with .ini files."""

    def __init__(self, *filenames: str | os.PathLike[str]) -> None:
        self.parser = ConfigParser()
        files: List[str] = []
        if not filenames:
            filenames = (DEFAULT_CONFIG_FILE,)
        for filename in filenames:
            path = Path(filename)
            if path.exists():
                files.append(str(path))
        if files:
            self.parser.read(files)

    def get(self, section: str, option: str, fallback: Optional[str] = None) -> str:
        if self.parser.has_option(section, option):
            return self.parser.get(section, option)
        if fallback is not None:
            return fallback
        raise KeyError(f"Missing configuration option {section}.{option}")

    def getint(self, section: str, option: str, fallback: Optional[int] = None) -> int:
        if self.parser.has_option(section, option):
            return self.parser.getint(section, option)
        if fallback is not None:
            return fallback
        raise KeyError(f"Missing configuration option {section}.{option}")

    def getboolean(self, section: str, option: str, fallback: Optional[bool] = None) -> bool:
        if self.parser.has_option(section, option):
            return self.parser.getboolean(section, option)
        if fallback is not None:
            return fallback
        raise KeyError(f"Missing configuration option {section}.{option}")

    def section(self, name: str) -> Dict[str, str]:
        if not self.parser.has_section(name):
            return {}
        return {k: v for k, v in self.parser.items(name)}


# Security helpers ---------------------------------------------------------

def generate_api_key() -> str:
    return secrets.token_hex(32)


def compute_signature(secret: str, subject_id: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), subject_id.encode("utf-8") + body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, subject_id: str, body: bytes, signature: str) -> bool:
    expected = compute_signature(secret, subject_id, body)
    return hmac.compare_digest(expected, signature)


# Simple vector store ------------------------------------------------------

@dataclass
class MemoryEntry:
    text: str
    vector: List[float]

    def to_dict(self) -> Dict[str, object]:
        return {"text": self.text, "vector": self.vector}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "MemoryEntry":
        return cls(text=str(data["text"]), vector=list(map(float, data["vector"])))


class SimpleVectorStore:
    """A lightweight on-disk vector store with cosine similarity search."""

    def __init__(self, path: Path, dim: int = 64) -> None:
        self.path = Path(path)
        self.dim = dim
        self._entries: List[MemoryEntry] = []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.load()

    # Internal helpers --------------------------------------------------
    def _text_to_vector(self, text: str) -> List[float]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        needed = self.dim * 4
        repeated = (digest * ((needed // len(digest)) + 1))[:needed]
        floats = []
        for idx in range(0, needed, 4):
            chunk = repeated[idx : idx + 4]
            value = int.from_bytes(chunk, "big", signed=False) / 0xFFFFFFFF
            floats.append(value)
        norm = math.sqrt(sum(x * x for x in floats))
        if norm == 0:
            return floats
        return [x / norm for x in floats]

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        return sum(x * y for x, y in zip(a, b))

    # Public API --------------------------------------------------------
    def add(self, text: str) -> MemoryEntry:
        vector = self._text_to_vector(text)
        entry = MemoryEntry(text=text, vector=vector)
        self._entries.append(entry)
        self.save()
        return entry

    def search(self, query: str, top_k: int = 5) -> List[MemoryEntry]:
        if not self._entries:
            return []
        query_vec = self._text_to_vector(query)
        scored = [
            (self._cosine_similarity(entry.vector, query_vec), entry)
            for entry in self._entries
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]

    def load(self) -> None:
        with self.path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._entries = [MemoryEntry.from_dict(item) for item in data]

    def save(self) -> None:
        with self.path.open("w", encoding="utf-8") as fh:
            json.dump([entry.to_dict() for entry in self._entries], fh, indent=2)

    def all(self) -> List[MemoryEntry]:
        return list(self._entries)


# Misc helpers -------------------------------------------------------------

def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json(path: Path) -> Dict[str, object]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(path: Path, data: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def month_key(dt) -> Tuple[int, int]:
    return dt.year, dt.month


__all__ = [
    "ConfigLoader",
    "generate_api_key",
    "compute_signature",
    "verify_signature",
    "SimpleVectorStore",
    "ensure_directory",
    "load_json",
    "dump_json",
    "MemoryEntry",
]
