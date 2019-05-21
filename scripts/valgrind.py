#!/bin/env python3

import subprocess
import json
from pprint import pprint
from functools import partial
from os import path
import os
from pathlib import Path

ignored = ["sessions"]

PROJECT_ROOT = Path(__file__).parent.parent
CARGO_TOML = PROJECT_ROOT.joinpath("libsignal-protocol", "Cargo.toml")


def examples(target_dir: Path):
    """
    Use `cargo manifest` to find the executable that corresponds to each of
    the library's examples.
    """
    manifest = get_manifest()

    for pkg in manifest["packages"]:
        if pkg["name"] == "libsignal-protocol":
            targets = pkg["targets"]

            for target in targets:
                if "example" in target["kind"] and target["name"] not in ignored:
                    yield target_dir.joinpath("debug", "examples", target["name"])


def get_manifest():
    args = ["cargo", "metadata", "--no-deps", "--format-version=1",
            "--manifest-path", str(CARGO_TOML)]

    output = subprocess.check_output(args)
    return json.loads(output.decode("utf-8"))


def integration_tests():
    """
    Get the executable corresponding to the crate's tests (excluding doc-tests).
    """
    args = ["cargo", "test", "--tests", "--no-run", "--message-format=json",
            "--manifest-path", str(CARGO_TOML)]
    output = subprocess.check_output(args)
    stdout = output.decode("utf-8")

    for line in stdout.splitlines():
        line = json.loads(line)
        if line["reason"] == "compiler-artifact" and "test" in line["target"]["kind"] and line.get("name") not in ignored:
            yield line["executable"]


def run_valgrind(original_cmd):
    args = ["valgrind", "--leak-check=full", "--trace-children=yes",
            "--show-leak-kinds=all", "--error-exitcode=1"]
    args.extend(original_cmd)

    env = os.environ.copy()
    env["RUST_BACKTRACE"] = "full"
    subprocess.check_call(args, env=env)


def main():
    binaries = []
    binaries.extend(examples(Path("target")))
    binaries.extend(integration_tests())

    for binary in binaries:
        run_valgrind([str(binary)])


if __name__ == "__main__":
    main()
