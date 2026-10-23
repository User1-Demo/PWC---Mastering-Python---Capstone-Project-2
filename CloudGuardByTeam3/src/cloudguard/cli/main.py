import argparse
import json
from urllib import parse, request

def main():
    parser=argparse.ArgumentParser(prog="cloudguard")
    parser.add_argument("command", choices=["health"]); parser.add_argument("--url", default="http://127.0.0.1:8000")
    args=parser.parse_args()
    if args.command == "health":
        with request.urlopen(parse.urljoin(args.url, "/api/v1/health")) as response:
            print(json.dumps(json.load(response), indent=2))
if __name__ == "__main__": main()
