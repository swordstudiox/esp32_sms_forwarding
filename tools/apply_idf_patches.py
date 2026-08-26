#!/usr/bin/env python3
"""为 ESP-IDF 应用仓库维护的 SDK patch。"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


PATCH_RELATIVE_PATH = Path(
    "patches/mbedtls/0001-x509-parse-all-certificate-policy-oids.patch"
)


def git_apply_check(repo: Path, patch: Path, reverse: bool = False) -> tuple[bool, str]:
    args = ["apply", "--check"]
    if reverse:
        args.append("--reverse")
    args.append(str(patch))
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    detail = (result.stderr or result.stdout).strip()
    return result.returncode == 0, detail


def resolve_idf_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    env_value = os.environ.get("IDF_PATH")
    if env_value:
        return Path(env_value).expanduser().resolve()
    raise RuntimeError("未提供 --idf-path，且环境变量 IDF_PATH 未设置")


def apply_patch(repo_root: Path, idf_path: Path, check_only: bool) -> None:
    mbedtls_path = idf_path / "components" / "mbedtls" / "mbedtls"
    patch_path = repo_root / PATCH_RELATIVE_PATH

    if not idf_path.is_dir():
        raise RuntimeError(f"ESP-IDF 路径不存在: {idf_path}")
    if not mbedtls_path.is_dir():
        raise RuntimeError(f"ESP-IDF vendored Mbed TLS 路径不存在: {mbedtls_path}")
    if not patch_path.is_file():
        raise RuntimeError(f"项目 patch 不存在: {patch_path}")

    # 不绑定外部 SDK 的 Git commit；只要求 patch 上下文完整匹配。
    can_apply, apply_detail = git_apply_check(mbedtls_path, patch_path)
    if can_apply:
        if check_only:
            print(f"patch 可应用: {patch_path}")
            return

        result = subprocess.run(
            [
                "git",
                "-C",
                str(mbedtls_path),
                "apply",
                "--whitespace=error",
                str(patch_path),
            ],
            check=False,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("应用 ESP-IDF Mbed TLS patch 失败")
        print(f"已应用 patch: {patch_path}")
        return

    already_applied, reverse_detail = git_apply_check(
        mbedtls_path, patch_path, reverse=True
    )
    if already_applied:
        print(f"patch 已经应用: {patch_path}")
        return

    detail = apply_detail or reverse_detail or "无详细错误"
    raise RuntimeError(
        "patch 既不能正向应用，也不能识别为已应用状态；"
        "拒绝 fuzzy/部分应用。\n"
        f"patch: {patch_path}\n{detail}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idf-path", help="ESP-IDF 根目录；默认读取 IDF_PATH")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="只检查 patch 状态，不修改 SDK",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    try:
        idf_path = resolve_idf_path(args.idf_path)
        apply_patch(repo_root, idf_path, args.check_only)
    except RuntimeError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
