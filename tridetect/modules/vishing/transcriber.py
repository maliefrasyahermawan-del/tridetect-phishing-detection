"""
Vishing transcriber — STUB (Phase 2).

Phase 2 plan:
- Accept audio file (WAV/MP3/M4A) or raw bytes
- Resample to 16kHz mono via librosa/soundfile
- Transcribe with openai-whisper (model: small/medium depending on resource)
- Return transcript string

Phase 3 plan:
- Voice clone / deepfake detection
- Speaker diarisation
"""

from typing import Optional


class VoiceTranscriber:
    def __init__(self, model_size: str = "small"):
        self._model_size = model_size
        raise NotImplementedError(
            "VoiceTranscriber is a Phase 2 stub. "
            "Install openai-whisper and implement transcribe() to activate."
        )

    def transcribe(self, audio_path: str, language: str = "id") -> Optional[str]:
        raise NotImplementedError("Phase 2 stub")
