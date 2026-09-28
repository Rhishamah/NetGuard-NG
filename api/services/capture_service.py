import asyncio
import os
import signal
import shutil


capture_lock = asyncio.Lock()


async def run_live_capture(
    interface: str,
    duration_seconds: int,
    output_path: str,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run CicFlowMeter for a fixed duration or until stop_event is set."""

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