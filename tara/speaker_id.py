"""Lightweight speaker check for TARA (numpy only, no heavy ML deps).

Turns a short clip of the wake word into an MFCC-based voiceprint and compares it to the
enrolled owner(s). It is a MODERATE check, not biometric-grade: good enough to tell the owner
from a clearly different voice or a TV in many rooms, but foolable by a close imp/recording.

Design rule used by TARA: a speaker verdict may only make the rules STRICTER (an unknown voice
adds friction), never looser. So even when this errs, security never drops below the baseline.

Voiceprints live in ~/tara/secrets/voiceprints.json (just numbers, no audio kept).
"""
import json
import os

import numpy as np

from core import SECRETS_DIR

PRINTS_PATH = os.path.join(SECRETS_DIR, "voiceprints.json")
SR = 16000
KNOWN_THRESHOLD = 0.72      # cosine similarity above this = same speaker (tunable, conservative)


def _mfcc(pcm, sr=SR, n_mfcc=13, n_mels=26, frame_ms=25, hop_ms=10, fmin=80, fmax=7600):
    x = pcm.astype(np.float32)
    if x.size < sr // 4:        # under ~0.25s is too little to judge
        return None
    x = np.append(x[0], x[1:] - 0.97 * x[:-1])      # pre-emphasis
    flen, hop = int(sr * frame_ms / 1000), int(sr * hop_ms / 1000)
    if x.size < flen:
        return None
    n = 1 + (x.size - flen) // hop
    idx = np.arange(flen)[None, :] + hop * np.arange(n)[:, None]
    frames = x[idx] * np.hamming(flen)
    nfft = 512
    mag = np.abs(np.fft.rfft(frames, nfft)) ** 2 / nfft
    # mel filterbank
    mel = lambda f: 2595 * np.log10(1 + f / 700)
    imel = lambda m: 700 * (10 ** (m / 2595) - 1)
    pts = imel(np.linspace(mel(fmin), mel(fmax), n_mels + 2))
    bins = np.floor((nfft + 1) * pts / sr).astype(int)
    fb = np.zeros((n_mels, nfft // 2 + 1))
    for i in range(1, n_mels + 1):
        for j in range(bins[i - 1], bins[i]):
            fb[i - 1, j] = (j - bins[i - 1]) / (bins[i] - bins[i - 1] + 1e-9)
        for j in range(bins[i], bins[i + 1]):
            fb[i - 1, j] = (bins[i + 1] - j) / (bins[i + 1] - bins[i] + 1e-9)
    feat = np.log(mag @ fb.T + 1e-6)
    # DCT-II -> keep low coefficients
    k = np.arange(n_mels)
    dct = np.cos(np.pi / n_mels * (k[:, None] + 0.5) * np.arange(n_mfcc)[None, :])
    m = feat @ dct      # frames x n_mfcc
    # Drop the first (energy) coefficient so loudness doesn't dominate.
    return m[:, 1:]


def embed(pcm):
    """A fixed-length voiceprint vector from PCM, or None if the clip is too short/quiet.

    Speaker-discriminative features come from the COVARIANCE of the MFCC trajectory (how the
    spectrum co-varies), not the mean (which is mostly phonetic content). Per-utterance
    cepstral mean-variance normalization removes channel/loudness first."""
    m = _mfcc(np.asarray(pcm, dtype=np.float32))
    if m is None or m.shape[0] < 8:
        return None
    # Voice-activity gate: keep the louder frames (drop silence).
    energy = np.sum(m ** 2, axis=1)
    keep = energy >= np.percentile(energy, 35)
    m = m[keep] if keep.sum() >= 8 else m
    # CMVN: zero mean, unit variance per coefficient within this utterance.
    m = (m - m.mean(0)) / (m.std(0) + 1e-6)
    delta = np.diff(m, axis=0, prepend=m[:1])
    feats = np.concatenate([m, delta], axis=1)      # frames x 2D
    cov = np.cov(feats, rowvar=False)               # (2D)x(2D) speaker-ish correlations
    iu = np.triu_indices(cov.shape[0])
    vec = cov[iu]                                   # upper triangle incl. diagonal
    norm = np.linalg.norm(vec)
    return (vec / norm) if norm > 0 else None


def pcm_from_wav(path):
    import wave
    with wave.open(path, "rb") as w:
        if w.getframerate() != SR or w.getnchannels() != 1 or w.getsampwidth() != 2:
            raise ValueError("enrollment audio must be 16 kHz mono 16-bit WAV")
        return np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32)


def _load():
    try:
        with open(PRINTS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(prints):
    os.makedirs(SECRETS_DIR, exist_ok=True)
    tmp = PRINTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(prints, f)
    os.replace(tmp, PRINTS_PATH)


def enroll(name, pcm_clips):
    """Store the average voiceprint for `name` from several clips (lists/arrays of int16)."""
    vecs = [v for v in (embed(c) for c in pcm_clips) if v is not None]
    if not vecs:
        raise ValueError("no usable audio in the enrollment clips")
    mean = np.mean(vecs, axis=0)
    mean /= np.linalg.norm(mean) + 1e-9
    prints = _load()
    prints[name] = mean.tolist()
    _save(prints)
    return len(vecs)


def identify(pcm):
    """Returns {'speaker': name|None, 'score': float, 'known': bool}. Enrolled -> best match;
    no enrollment -> unknown (TARA then just keeps the baseline rules)."""
    prints = _load()
    v = embed(pcm)
    if v is None:
        return {"speaker": None, "score": 0.0, "known": False, "reason": "clip too short or quiet"}
    if not prints:
        return {"speaker": None, "score": 0.0, "known": False, "reason": "no voices enrolled"}
    scores = {name: float(np.dot(v, np.asarray(vec))) for name, vec in prints.items()}
    best = max(scores, key=scores.get)
    return {"speaker": best if scores[best] >= KNOWN_THRESHOLD else None,
            "score": round(scores[best], 3), "known": scores[best] >= KNOWN_THRESHOLD,
            "all_scores": {k: round(s, 3) for k, s in scores.items()}}
