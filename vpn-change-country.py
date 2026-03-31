#!/usr/bin/env python3
"""
vpn-change-country.py

Force a Gluetun/Mullvad service (for example `vpn-stable`) to reconnect using
ONE selected country from a pool, recreating the VPN service and any extra
Compose services you list.

Why this exists:
- Gluetun's SERVER_COUNTRIES is a FILTER, not a round-robin rotation list.
- Recreating the container with the same country pool can reconnect to the same
  country again.
- This script temporarily generates an override env file with
  SERVER_COUNTRIES=<chosen_country>, recreates the VPN service, optionally
  recreates sibling services, verifies the result, and leaves your original
  .env untouched unless you explicitly request --write-back.

Typical usage:
  python vpn-change-country.py \
    --compose-file docker-compose.yml \
    --env-file .env \
    --vpn-service vpn-stable \
    --countries Finland,Switzerland,Sweden,Denmark \
    --recreate dispatcharr dispatcharr-ip-exporter

If --countries is omitted, the script reads SERVER_COUNTRIES from the env file.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import socket
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


DEFAULT_GEO_URLS = (
    "https://ipapi.co/json/",
    "https://ipinfo.io/json",
    "https://ifconfig.co/json",
)

MULLVAD_RELAYS_URLS = (
    "https://api.mullvad.net/public/relays/wireguard/v2",
    "https://api.mullvad.net/public/relays/wireguard/v1/",
)


class ScriptError(RuntimeError):
    pass


def wants_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


USE_COLOR = wants_color()


def style(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(text: str) -> str:
    return style(text, "1")


def dim(text: str) -> str:
    return style(text, "2")


def green(text: str) -> str:
    return style(text, "32")


def yellow(text: str) -> str:
    return style(text, "33")


def blue(text: str) -> str:
    return style(text, "34")


def magenta(text: str) -> str:
    return style(text, "35")


def cyan(text: str) -> str:
    return style(text, "36")


def red(text: str) -> str:
    return style(text, "31")


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


class ColorHelpFormatter(argparse.RawTextHelpFormatter):
    def start_section(self, heading: str) -> None:
        super().start_section(cyan(bold(heading)))

    def _format_action_invocation(self, action: argparse.Action) -> str:
        text = super()._format_action_invocation(action)
        return yellow(text)

    def _format_usage(
        self,
        usage: Optional[str],
        actions: Sequence[argparse.Action],
        groups: Sequence[argparse._MutuallyExclusiveGroup],
        prefix: Optional[str],
    ) -> str:
        if prefix is None:
            prefix = bold(cyan("usage: "))
        else:
            prefix = bold(cyan(prefix))
        return super()._format_usage(usage, actions, groups, prefix)


def build_epilog() -> str:
    return f"""{bold('Examples:')}

  {green('PowerShell - normal use')}
    python .\\vpn-change-country.py --compose-file .\\docker-compose.yml --env-file .\\.env --vpn-service vpn-stable --recreate dispatcharr dispatcharr-ip-exporter

  {green('PowerShell - with explicit pool')}
    python .\\vpn-change-country.py --compose-file .\\docker-compose.yml --env-file .\\.env --vpn-service vpn-stable --countries Finland,Switzerland,Sweden,Denmark --recreate dispatcharr dispatcharr-ip-exporter

  {green('PowerShell - dry run')}
    python .\\vpn-change-country.py --compose-file .\\docker-compose.yml --env-file .\\.env --vpn-service vpn-stable --recreate dispatcharr dispatcharr-ip-exporter --dry-run

  {green('PowerShell - persist chosen country into the real .env')}
    python .\\vpn-change-country.py --compose-file .\\docker-compose.yml --env-file .\\.env --vpn-service vpn-stable --recreate dispatcharr dispatcharr-ip-exporter --write-back

  {green('PowerShell - list Mullvad country names')}
    python .\\vpn-change-country.py --country-list

  {green('CMD.EXE - multiline')}
    python vpn-change-country.py ^
      --compose-file docker-compose.yml ^
      --env-file .env ^
      --vpn-service vpn-stable ^
      --recreate dispatcharr dispatcharr-ip-exporter

{bold('Important notes:')}
  - {yellow('--country-list')} must be used {bold('alone')} as the only argument.
  - {yellow('--recreate')} expects {bold('Compose service names')}, not arbitrary container labels.
  - {yellow('--countries')} overrides SERVER_COUNTRIES from the .env for that execution.
  - Without {yellow('--write-back')}, your original .env is left untouched.
  - PowerShell line continuation uses the backtick: {yellow('`')} ; {bold('not')} {yellow('^')}.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"{bold('Force a Gluetun VPN service to switch country and recreate selected services.')}\n\n"
            f"{dim('What it really does:')}\n"
            f"  - picks one country from a pool\n"
            f"  - creates an effective env with SERVER_COUNTRIES=<that country>\n"
            f"  - recreates the VPN compose service\n"
            f"  - optionally recreates additional dependent services\n"
            f"  - verifies the final country/IP when possible\n\n"
            f"{dim('What it does NOT do:')}\n"
            f"  - it does not make Gluetun rotate automatically forever\n"
            f"  - it does not make SERVER_COUNTRIES behave like round-robin\n"
            f"  - it does not modify your real .env unless you pass --write-back"
        ),
        formatter_class=ColorHelpFormatter,
        epilog=build_epilog(),
    )
    parser.add_argument(
        "--country-list",
        action="store_true",
        help=(
            "Print the country names currently exposed by Mullvad's public relay API.\n"
            "This flag is only valid when used alone: python vpn-change-country.py --country-list"
        ),
    )
    parser.add_argument(
        "--compose-file",
        default="docker-compose.yml",
        help="Path to docker-compose.yml (default: docker-compose.yml)",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Path to .env file used by Compose (default: .env)",
    )
    parser.add_argument(
        "--vpn-service",
        default="vpn-stable",
        help="Compose service name of the Gluetun container (default: vpn-stable)",
    )
    parser.add_argument(
        "--vpn-container",
        default=None,
        help=(
            "Docker container name for the VPN service. Defaults to the same value as --vpn-service.\n"
            "Useful if service name and container_name differ."
        ),
    )
    parser.add_argument(
        "--countries",
        default=None,
        help=(
            "Comma-separated pool of countries to choose from.\n"
            "If omitted, uses SERVER_COUNTRIES from the env file.\n"
            "Example: Finland,Switzerland,Sweden,Denmark"
        ),
    )
    parser.add_argument(
        "--pick",
        default="random",
        choices=("random", "first", "last"),
        help=(
            "How to choose the next country from the pool (default: random)\n"
            "  random -> choose any allowed country except current if possible\n"
            "  first  -> pick the first valid country in the pool\n"
            "  last   -> pick the last valid country in the pool"
        ),
    )
    parser.add_argument(
        "--current-country",
        default=None,
        help=(
            "Optional current country name/code to exclude from selection.\n"
            "If omitted, the script tries to detect the current VPN country automatically."
        ),
    )
    parser.add_argument(
        "--recreate",
        nargs="*",
        default=[],
        help=(
            "Additional Compose services to force-recreate after the VPN service.\n"
            "Example: --recreate dispatcharr dispatcharr-ip-exporter"
        ),
    )
    parser.add_argument(
        "--write-back",
        action="store_true",
        help="Persist the chosen country back into the original env file as SERVER_COUNTRIES=<country>.",
    )
    parser.add_argument(
        "--health-timeout",
        type=int,
        default=120,
        help="Seconds to wait for vpn container healthy/running (default: 120)",
    )
    parser.add_argument(
        "--geo-timeout",
        type=int,
        default=20,
        help="Seconds timeout for each geo lookup attempt (default: 20)",
    )
    parser.add_argument(
        "--compose-bin",
        default="auto",
        help="Compose command to use: 'auto', 'docker compose', or 'docker-compose' (default: auto)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without recreating anything.",
    )
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.country_list:
        raw_argv = sys.argv[1:] if argv is None else list(argv)
        if len(raw_argv) != 1:
            parser.error("--country-list only works when it is the only argument.")
    return args


def detect_compose_command(choice: str) -> List[str]:
    if choice != "auto":
        return shlex.split(choice)

    candidates: List[List[str]] = [["docker", "compose"], ["docker-compose"]]
    for candidate in candidates:
        try:
            result = subprocess.run(
                candidate + ["version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            continue
        if result.returncode == 0:
            return candidate

    raise ScriptError(
        "No Compose command available. Install Docker Compose v2 ('docker compose') or legacy 'docker-compose'."
    )


def run_cmd(
    cmd: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        raise ScriptError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{stdout or '(empty)'}\n"
            f"STDERR:\n{stderr or '(empty)'}"
        )
    return result


def read_env_file(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1").splitlines()


def parse_env_map(lines: Sequence[str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = raw_line.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def update_env_lines(lines: Sequence[str], key: str, value: str) -> List[str]:
    updated: List[str] = []
    replaced = False
    for line in lines:
        if not replaced and line.strip().startswith(f"{key}="):
            updated.append(f"{key}={value}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(f"{key}={value}")
    return updated


def split_countries(csv_value: str) -> List[str]:
    countries = [part.strip() for part in csv_value.split(",") if part.strip()]
    unique: List[str] = []
    seen = set()
    for country in countries:
        key = country.casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(country)
    return unique


def normalize_country(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value.strip().casefold() or None


def choose_country(pool: Sequence[str], current: Optional[str], mode: str) -> str:
    if not pool:
        raise ScriptError("The country pool is empty.")

    normalized_current = normalize_country(current)
    filtered = [c for c in pool if normalize_country(c) != normalized_current]
    candidates = filtered if filtered else list(pool)

    if mode == "first":
        return candidates[0]
    if mode == "last":
        return candidates[-1]
    return random.choice(candidates)


def docker_inspect_health(container_name: str) -> Optional[str]:
    fmt = "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}"
    result = run_cmd(["docker", "inspect", "-f", fmt, container_name], check=False)
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def wait_for_container(container_name: str, timeout: int) -> str:
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        status = docker_inspect_health(container_name)
        if status:
            last_status = status
            if status in {"healthy", "running"}:
                return status
        time.sleep(2)
    raise ScriptError(
        f"Container '{container_name}' did not become healthy/running within {timeout}s. "
        f"Last observed status: {last_status or 'unknown'}"
    )


def probe_geo_from_vpn(container_name: str, timeout: int) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    for url in DEFAULT_GEO_URLS:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{container_name}",
            "alpine:3.20",
            "sh",
            "-lc",
            f"wget -qO- {shlex.quote(url)}",
        ]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode != 0 or not result.stdout.strip():
            continue
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            continue

        country = (
            payload.get("country_name")
            or payload.get("country")
            or payload.get("countryCode")
            or payload.get("country_code")
        )
        region = payload.get("region") or payload.get("region_name")
        ip_addr = payload.get("ip") or payload.get("ip_addr") or payload.get("query")

        if isinstance(country, str):
            country = country.strip()
        if isinstance(region, str):
            region = region.strip()
        if isinstance(ip_addr, str):
            ip_addr = ip_addr.strip()

        return country, region, ip_addr

    return None, None, None


def fetch_json(url: str, timeout: int = 20) -> object:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "vpn-change-country.py/1.0",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - public read-only API
        charset = resp.headers.get_content_charset() or "utf-8"
        body = resp.read().decode(charset, errors="replace")
    return json.loads(body)


def iter_country_names_from_payload(payload: object) -> Iterable[str]:
    if isinstance(payload, dict):
        countries = payload.get("countries")
        if isinstance(countries, list):
            for item in countries:
                if isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str) and name.strip():
                        yield name.strip()
        locations = payload.get("locations")
        if isinstance(locations, list):
            for item in locations:
                if isinstance(item, dict):
                    country = item.get("country")
                    if isinstance(country, str) and country.strip():
                        yield country.strip()
        # recursive fallback
        for value in payload.values():
            yield from iter_country_names_from_payload(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from iter_country_names_from_payload(item)


def dedupe_sort_names(names_iter: Iterable[str]) -> List[str]:
    names: List[str] = []
    seen = set()
    for name in names_iter:
        if not isinstance(name, str):
            continue
        cleaned = name.strip()
        if not cleaned:
            continue
        key = cleaned.casefold()
        if key in seen:
            continue
        seen.add(key)
        names.append(cleaned)
    return sorted(names, key=lambda s: s.casefold())


def fetch_json_via_docker(url: str, timeout: int = 20) -> object:
    cmd = [
        "docker",
        "run",
        "--rm",
        "alpine:3.20",
        "sh",
        "-lc",
        f"wget -qO- {shlex.quote(url)}",
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ScriptError(
            "dockerized fetch failed: " + (result.stderr.strip() or result.stdout.strip() or "unknown error")
        )
    return json.loads(result.stdout)


def extract_provider_payload(payload: object, provider_names: Sequence[str]) -> Optional[object]:
    wanted = {name.casefold() for name in provider_names}
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key.casefold() in wanted:
                return value
        for value in payload.values():
            found = extract_provider_payload(value, provider_names)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for item in payload:
            found = extract_provider_payload(item, provider_names)
            if found is not None:
                return found
    return None


def read_gluetun_servers_json_from_container(container_name: str) -> object:
    cmd = ["docker", "exec", container_name, "sh", "-lc", "cat /gluetun/servers.json"]
    result = run_cmd(cmd, check=False)
    if result.returncode != 0 or not (result.stdout or "").strip():
        raise ScriptError(
            f"could not read /gluetun/servers.json from container {container_name}: "
            f"{(result.stderr or result.stdout or 'empty output').strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ScriptError(f"invalid JSON in /gluetun/servers.json: {exc}") from exc


def get_mullvad_country_names(timeout: int = 20, vpn_container: str = "vpn-stable") -> List[str]:
    errors: List[str] = []

    for url in MULLVAD_RELAYS_URLS:
        try:
            payload = fetch_json(url, timeout=timeout)
            names = dedupe_sort_names(iter_country_names_from_payload(payload))
            if names:
                return names
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, urllib.error.URLError) and isinstance(getattr(exc, "reason", None), socket.gaierror):
                errors.append(f"host DNS failed for {url}: {exc.reason}")
            else:
                errors.append(f"host fetch failed for {url}: {exc}")

    for url in MULLVAD_RELAYS_URLS:
        try:
            payload = fetch_json_via_docker(url, timeout=timeout)
            names = dedupe_sort_names(iter_country_names_from_payload(payload))
            if names:
                return names
        except Exception as exc:  # noqa: BLE001
            errors.append(f"docker fetch failed for {url}: {exc}")

    try:
        payload = read_gluetun_servers_json_from_container(vpn_container)
        provider_payload = extract_provider_payload(payload, ("mullvad",)) or payload
        names = dedupe_sort_names(iter_country_names_from_payload(provider_payload))
        if names:
            return names
        errors.append(f"/gluetun/servers.json in {vpn_container} did not contain Mullvad country names")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"local Gluetun servers fallback failed: {exc}")

    raise ScriptError(
        "Could not obtain the Mullvad country list. Tried: host public API, Dockerized public API, "
        f"and /gluetun/servers.json from container '{vpn_container}'. Details: " + " | ".join(errors)
    )


def print_in_columns(items: Sequence[str]) -> None:
    if not items:
        print(yellow("No countries found."))
        return

    width = shutil.get_terminal_size((120, 25)).columns
    max_item = max(len(item) for item in items)
    col_width = max_item + 3
    cols = max(1, width // max(col_width, 1))
    rows = (len(items) + cols - 1) // cols

    matrix: List[List[str]] = []
    for r in range(rows):
        row: List[str] = []
        for c in range(cols):
            idx = c * rows + r
            if idx < len(items):
                row.append(items[idx])
        matrix.append(row)

    for row in matrix:
        line = "".join(f"{item:<{col_width}}" for item in row).rstrip()
        print(line)


def compose_base_args(compose_cmd: Sequence[str], compose_file: Path, env_file: Path) -> List[str]:
    return list(compose_cmd) + ["-f", str(compose_file), "--env-file", str(env_file)]


def recreate_services(
    compose_cmd: Sequence[str],
    compose_file: Path,
    env_file: Path,
    services: Sequence[str],
    *,
    cwd: Path,
    dry_run: bool,
) -> None:
    if not services:
        return
    cmd = compose_base_args(compose_cmd, compose_file, env_file) + [
        "up",
        "-d",
        "--force-recreate",
        "--no-deps",
        *services,
    ]
    if dry_run:
        print(dim("[dry-run]"), " ".join(shlex.quote(part) for part in cmd))
        return
    run_cmd(cmd, cwd=cwd, capture=True)


def print_summary_row(label: str, value: str) -> None:
    print(f"{bold(cyan(label + ':')):<18} {value}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    if args.country_list:
        countries = get_mullvad_country_names(vpn_container="vpn-stable")
        print(bold(cyan("Mullvad country names valid for SERVER_COUNTRIES")))
        print(dim("Use these exact names with --countries or in SERVER_COUNTRIES.\n"))
        print_in_columns(countries)
        print()
        print(dim(f"Total: {len(countries)} countries"))
        return 0

    compose_file = Path(args.compose_file).expanduser().resolve()
    env_file = Path(args.env_file).expanduser().resolve()
    compose_dir = compose_file.parent
    vpn_service = args.vpn_service
    vpn_container = args.vpn_container or vpn_service

    if not compose_file.exists():
        raise ScriptError(f"Compose file not found: {compose_file}")
    if not env_file.exists():
        raise ScriptError(f"Env file not found: {env_file}")

    compose_cmd = detect_compose_command(args.compose_bin)

    env_lines = read_env_file(env_file)
    env_map = parse_env_map(env_lines)

    raw_pool = args.countries or env_map.get("SERVER_COUNTRIES", "")
    pool = split_countries(raw_pool)
    if not pool:
        raise ScriptError(
            "No country pool available. Pass --countries or define SERVER_COUNTRIES in the env file."
        )

    detected_country = None
    detected_region = None
    detected_ip = None

    current_country = args.current_country
    if current_country is None:
        detected_country, detected_region, detected_ip = probe_geo_from_vpn(vpn_container, args.geo_timeout)
        current_country = detected_country

    chosen_country = choose_country(pool, current_country, args.pick)

    print_summary_row("Compose command", " ".join(compose_cmd))
    print_summary_row("Compose file", str(compose_file))
    print_summary_row("Env file", str(env_file))
    print_summary_row("VPN service", vpn_service)
    print_summary_row("VPN container", vpn_container)
    print_summary_row("Country pool", ", ".join(pool))
    print_summary_row("Current country", current_country or dim("unknown"))
    if detected_region:
        print_summary_row("Current region", detected_region)
    if detected_ip:
        print_summary_row("Current public IP", detected_ip)
    print_summary_row("Chosen country", green(chosen_country))
    if args.recreate:
        print_summary_row("Extra recreate", ", ".join(args.recreate))

    temp_env_path: Optional[Path] = None

    if args.write_back:
        updated_lines = update_env_lines(env_lines, "SERVER_COUNTRIES", chosen_country)
        if args.dry_run:
            print(dim(f"[dry-run] would write back SERVER_COUNTRIES={chosen_country} to {env_file}"))
            effective_env_file = env_file
        else:
            backup_path = env_file.with_suffix(env_file.suffix + ".bak")
            shutil.copy2(env_file, backup_path)
            env_file.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
            print_summary_row("Backup written", str(backup_path))
            effective_env_file = env_file
    else:
        updated_lines = update_env_lines(env_lines, "SERVER_COUNTRIES", chosen_country)
        temp_handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="vpn-country-",
            suffix=".env",
            delete=False,
        )
        with temp_handle:
            temp_handle.write("\n".join(updated_lines) + "\n")
        temp_env_path = Path(temp_handle.name)
        effective_env_file = temp_env_path
        print_summary_row("Temp env file", str(effective_env_file))

    try:
        recreate_services(
            compose_cmd,
            compose_file,
            effective_env_file,
            [vpn_service],
            cwd=compose_dir,
            dry_run=args.dry_run,
        )

        if not args.dry_run:
            final_status = wait_for_container(vpn_container, args.health_timeout)
            print_summary_row("VPN status", green(final_status))

        if args.recreate:
            recreate_services(
                compose_cmd,
                compose_file,
                effective_env_file,
                args.recreate,
                cwd=compose_dir,
                dry_run=args.dry_run,
            )

        if not args.dry_run:
            new_country, new_region, new_ip = probe_geo_from_vpn(vpn_container, args.geo_timeout)
            print_summary_row("New country", new_country or dim("unknown"))
            if new_region:
                print_summary_row("New region", new_region)
            if new_ip:
                print_summary_row("New public IP", new_ip)

            if new_country and normalize_country(new_country) == normalize_country(current_country):
                print(
                    yellow(
                        "Warning: the detected country is still the same as before. "
                        "This can happen if the geo API failed previously, the provider routed to the same country, "
                        "or the country labels differ."
                    )
                )

        print(green("Done."))
        return 0
    finally:
        if temp_env_path and temp_env_path.exists():
            try:
                temp_env_path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScriptError as exc:
        eprint(red(f"ERROR: {exc}"))
        raise SystemExit(1)
    except KeyboardInterrupt:
        eprint(yellow("Interrupted."))
        raise SystemExit(130)
