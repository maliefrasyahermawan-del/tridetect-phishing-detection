"""
Vishing classifier — STUB (Phase 2).

Delegates transcript classification to the Smishing module once
VoiceTranscriber is implemented.
"""

from typing import Any, Dict


class VishingClassifier:
    def __init__(self):
        raise NotImplementedError(
            "VishingClassifier is a Phase 2 stub. "
            "Implement VoiceTranscriber first, then wire it here."
        )

    def classify(self, audio_path: str, language: str = "id") -> Dict[str, Any]:
        raise NotImplementedError("Phase 2 stub")
