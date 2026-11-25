import asyncio
import os
import signal
import shutil
from datetime import datetime
from pathlib import Path


capture_lock = asyncio.Lock()

# All capture CSVs must live here. Paths are never taken from API requests.
CAPTURE_DIR = Path("data") / "captures"


def new_capture_path(prefix: str = "capture") -> str:
    """Server-generated, timestamped capture path inside CAPTURE_DIR."""
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return str(CAPTURE_DIR / f"{prefix}_{stamp}.csv")


def ensure_safe_output_path(output_path: str) -> str:
    """Refuse any output path that resolves outside CAPTURE_DIR.

    Defence in depth: run_live_capture deletes and rewrites this file, so a
    caller-controlled path (for example ../../.env) must never reach it.
    """
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    resolved = Path(output_path).resolve()
    if not resolved.is_relative_to(CAPTURE_DIR.resolve()):
        raise RuntimeError(f"Capture output must be inside {CAPTURE_DIR}/")
    return str(resolved)


async def run_live_capture(
    interface: str,
    duration_seconds: int,
    output_path: str,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run CicFlowMeter for a fixed duration or until stop_event is set."""

    output_path = ensure_safe_output_path(output_path)

    cicflowmeter_path = shutil.which("cicflowmeter")

    print(
        f"[DEBUG] cicflowmeter_path resolved to: {cicflowmeter_path}",
        flush=True,
    )

    if cicflowmeter_path is None:
        raise RuntimeError("cicflowmeter not found in PATH")

    if os.path.exists(output_path):
        os.remove(output_path)

    print(
        f"[DEBUG] Starting CicFlowMeter on {interface} "
        f"for {duration_seconds}s",
        flush=True,
    )

    process = await asyncio.create_subprocess_exec(
        cicflowmeter_path,
        "-i",
        interface,
        "-c",
        output_path,
    )

    try:
        if stop_event is None:
            await asyncio.sleep(duration_seconds)
        else:
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=duration_seconds,
                )
                print("[DEBUG] Stop requested", flush=True)
            except asyncio.TimeoutError:
                print("[DEBUG] Capture duration reached", flush=True)

        if process.returncode is None:
            print("[DEBUG] Sending SIGINT", flush=True)
            process.send_signal(signal.SIGINT)

        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=10,
            )
        except asyncio.TimeoutError:
            print(
                "[DEBUG] CicFlowMeter did not exit after SIGINT; "
                "sending SIGTERM",
                flush=True,
            )

            process.terminate()

            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=5,
                )
            except asyncio.TimeoutError:
                print(
                    "[DEBUG] CicFlowMeter still running; killing process",
                    flush=True,
                )
                process.kill()
                await process.wait()

    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

    print(
        f"[DEBUG] return code: {process.returncode}",
        flush=True,
    )

    if not os.path.exists(output_path):
        raise RuntimeError(
            f"CicFlowMeter did not create output file: {output_path}"
        )

    if os.path.getsize(output_path) == 0:
        raise RuntimeError(
            f"CicFlowMeter created an empty capture file: {output_path}"
        )

    print(
        f"[DEBUG] Capture file created: {output_path} "
        f"({os.path.getsize(output_path)} bytes)",
        flush=True,
    )