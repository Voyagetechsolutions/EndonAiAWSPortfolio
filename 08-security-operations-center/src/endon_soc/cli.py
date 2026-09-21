"""Command line for the SOC.

endon-soc summary            # print the board from the live DynamoDB tables
endon-soc demo               # print the board from the offline sample platform snapshot
endon-soc serve              # run the web console locally (needs uvicorn)
"""

from __future__ import annotations

import argparse

from endon_core.aws import ClientFactory
from endon_core.config import Settings
from endon_soc import report
from endon_soc.app import create_app
from endon_soc.demo import seed_stores
from endon_soc.service import SocService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="endon-soc", description="Endon AI SOC dashboard.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="print the board from the offline sample snapshot")
    sub.add_parser("summary", help="print the board from the live incident/finding tables")
    serve = sub.add_parser("serve", help="run the web console locally")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--demo", action="store_true", help="serve the offline sample snapshot")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        incidents, findings = seed_stores()
        print(report.render_console(SocService(incidents, findings)))
        return 0
    if args.command == "summary":
        print(report.render_console(_live_service()))
        return 0
    if args.command == "serve":
        return _serve(args)
    return 1


def _live_service() -> SocService:
    from endon_soc.wiring import build_live_service

    settings = Settings.from_env()
    return build_live_service(settings, ClientFactory(region=settings.region))


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed; install it to run the local server.")
        return 1

    if args.demo:
        incidents, findings = seed_stores()
        service = SocService(incidents, findings)
        account, region = "123456789012", "us-east-1"
    else:
        settings = Settings.from_env()
        service = _live_service()
        account, region = "", settings.region

    app = create_app(service, account_id=account, region=region)
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
