"""
memory.py

Persistent Long-Term Memory for all autonomous agents.

Current Storage:
    • JSON File

Future Upgrade:
    • ChromaDB
    • FAISS
    • Neo4j
    • PostgreSQL
"""

import json
import os
from collections import defaultdict


MEMORY_FILE = "memory_store.json"


class MemoryManager:

    def __init__(self):

        self.memory = defaultdict(list)

        self._load_memory()

    # -------------------------------------------------
    # Load Memory
    # -------------------------------------------------

    def _load_memory(self):

        if not os.path.exists(MEMORY_FILE):
            return

        try:

            with open(MEMORY_FILE, "r") as f:

                data = json.load(f)

                self.memory = defaultdict(list, data)

        except Exception:

            self.memory = defaultdict(list)

    # -------------------------------------------------
    # Save Memory
    # -------------------------------------------------

    def _save_memory(self):

        with open(MEMORY_FILE, "w") as f:

            json.dump(
                dict(self.memory),
                f,
                indent=4
            )

    # -------------------------------------------------
    # Store Observation
    # -------------------------------------------------

    def remember(
        self,
        category,
        item,
    ):

        if item not in self.memory[category]:

            self.memory[category].append(item)

            self._save_memory()

    # -------------------------------------------------
    # Recall Category
    # -------------------------------------------------

    def recall(
        self,
        category,
    ):

        return self.memory.get(category, [])

    # -------------------------------------------------
    # Check Memory
    # -------------------------------------------------

    def contains(
        self,
        category,
        item,
    ):

        return item in self.memory.get(category, [])

    # -------------------------------------------------
    # Forget One Item
    # -------------------------------------------------

    def forget(
        self,
        category,
        item,
    ):

        if item in self.memory.get(category, []):

            self.memory[category].remove(item)

            self._save_memory()

    # -------------------------------------------------
    # Clear One Category
    # -------------------------------------------------

    def clear_category(
        self,
        category,
    ):

        self.memory[category] = []

        self._save_memory()

    # -------------------------------------------------
    # Clear Entire Memory
    # -------------------------------------------------

    def clear_all(self):

        self.memory.clear()

        self._save_memory()

    # -------------------------------------------------
    # Dump Memory
    # -------------------------------------------------

    def dump(self):

        return dict(self.memory)

    # -------------------------------------------------
    # Statistics
    # -------------------------------------------------

    def stats(self):

        return {
            category: len(items)
            for category, items in self.memory.items()
        }


# ---------------------------------------------------------
# Global Shared Memory
# ---------------------------------------------------------

shared_memory = MemoryManager()