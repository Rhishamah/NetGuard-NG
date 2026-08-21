import asyncio
import shutil

capture_lock = asyncio.Lock()

async def run_live_capture(interface: str, duration_seconds: int, output_path: str) -> None:
    """Run cicflowmeter as a subprocess for a fixed duration, capturing flows to output_path."""
    cicflowmeter_path = shutil.which("cicflowmeter")
    if cicflowmeter_path is None:
        raise RuntimeError("cicflowmeter not found in PATH")

    process = await asyncio.create_subprocess_exec(
        "sudo", cicflowmeter_path, "-i", interface, "-c", output_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        await asyncio.wait_for(process.wait(), timeout=duration_seconds)
    except asyncio.TimeoutError:
        process.terminate()
        await process.wait()