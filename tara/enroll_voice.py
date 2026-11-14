"""Owner-only: enroll your voice so TARA can tell you from other people. Run on the laptop.

  python enroll_voice.py add "Manju" 4      # record 4 short clips of you saying "TARA ..."
  python enroll_voice.py list
  python enroll_voice.py remove "Manju"
  python enroll_voice.py check <file.wav>   # score a 16 kHz mono WAV against enrolled voices

Enrolling is deliberately not a voice or agent action. Voice identity only ever makes TARA
STRICTER (an unknown voice asks for the code), so a mediocre match can add friction but never
grants anything. Only voiceprints (numbers) are stored, never audio.
"""
import sys
import time
import wave

import numpy as np

import speaker_id


def record(seconds=2.2, sr=16000):
    import pyaudiowpatch as pyaudio
    pa = pyaudio.PyAudio()
    dev = pa.get_default_input_device_info()
    stream = pa.open(format=pyaudio.paInt16, channels=1, rate=sr, input=True,
                     input_device_index=dev["index"], frames_per_buffer=1024)
    frames = []
    for _ in range(int(sr / 1024 * seconds)):
        frames.append(stream.read(1024, exception_on_overflow=False))
    stream.stop_stream(); stream.close(); pa.terminate()
    return np.frombuffer(b"".join(frames), dtype=np.int16).astype(np.float32)


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "list"
    if cmd == "list":
        import json
        import os
        try:
            with open(speaker_id.PRINTS_PATH, encoding="utf-8") as f:
                print("Enrolled voices:", ", ".join(json.load(f).keys()) or "(none)")
        except (OSError, ValueError):
            print("Enrolled voices: (none)")
        return
    if cmd == "remove" and len(args) == 2:
        import json
        import os
        try:
            with open(speaker_id.PRINTS_PATH, encoding="utf-8") as f:
                prints = json.load(f)
        except (OSError, ValueError):
            prints = {}
        prints.pop(args[1], None)
        with open(speaker_id.PRINTS_PATH, "w", encoding="utf-8") as f:
            json.dump(prints, f)
        print(f"Removed '{args[1]}'.")
        return
    if cmd == "check" and len(args) == 2:
        print(speaker_id.identify(speaker_id.pcm_from_wav(args[1])))
        return
    if cmd == "add" and len(args) >= 2:
        name = args[1]
        n = int(args[2]) if len(args) > 2 else 4
        print(f"Recording {n} clips for '{name}'. After each 'GO', say: TARA, call my daughter "
              f"(or any short sentence starting with TARA).")
        clips = []
        for i in range(n):
            input(f"  clip {i + 1}/{n}: press Enter, then speak when it says GO...")
            print("  GO - speak now")
            clips.append(record())
            print("  got it")
        count = speaker_id.enroll(name, clips)
        print(f"\nEnrolled '{name}' from {count} clips. Self-check scores (same voice should be high):")
        for i, c in enumerate(clips):
            print(f"  clip {i + 1}: {speaker_id.identify(c)}")
        print("\nVoice identity is active. An unrecognized voice will now be asked for the code on "
              "sensitive actions. Remove with: python enroll_voice.py remove \"%s\"" % name)
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()
