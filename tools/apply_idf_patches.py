#!/usr/bin/env python3
"""为 ESP-IDF 应用仓库维护的 SDK patch。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
import sys


MBEDTLS_PATCH_RELATIVE_PATH = Path(
    "patches/mbedtls/0001-x509-parse-all-certificate-policy-oids.patch"
)
IDF_CRT_BUNDLE_PATCH_RELATIVE_PATH = Path(
    "patches/esp-idf/0001-crt-bundle-cross-signed-memory-leak.patch"
)


@dataclass(frozen=True)
class PatchTarget:
    label: str
    repo: Path
    patch: Path


def git_apply_check(repo: Path, patch: Path, reverse: bool = False) -> tuple[bool, str]:
    args = ["apply", "--check"]
    if reverse:
        args.append("--reverse")
    else:
        # 与实际正向写入保持同一空白规则，避免全部预检通过后才在第二个补丁失败。
        # 反向检查只用于识别“已应用”，不能加此参数：清理旧尾随空格的补丁
        # 反向后会重新引入旧空白，严格检查会把合法的已应用状态误判为损坏。
        args.append("--whitespace=error")
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


def patch_state(target: PatchTarget) -> tuple[str, str]:
    can_apply, apply_detail = git_apply_check(target.repo, target.patch)
    if can_apply:
        return "apply", ""

    already_applied, reverse_detail = git_apply_check(
        target.repo, target.patch, reverse=True
    )
    if already_applied:
        return "applied", ""

    detail = apply_detail or reverse_detail or "无详细错误"
    return "invalid", detail


def apply_patches(repo_root: Path, idf_path: Path, check_only: bool) -> None:
    mbedtls_path = idf_path / "components" / "mbedtls" / "mbedtls"
    crt_bundle_source = (
        idf_path / "components" / "mbedtls" / "esp_crt_bundle" / "esp_crt_bundle.c"
    )
    mbedtls_patch = repo_root / MBEDTLS_PATCH_RELATIVE_PATH
    crt_bundle_patch = repo_root / IDF_CRT_BUNDLE_PATCH_RELATIVE_PATH

    if not idf_path.is_dir():
        raise RuntimeError(f"ESP-IDF 路径不存在: {idf_path}")
    if not mbedtls_path.is_dir():
        raise RuntimeError(f"ESP-IDF vendored Mbed TLS 路径不存在: {mbedtls_path}")
    for patch in (mbedtls_patch, crt_bundle_patch):
        if not patch.is_file():
            raise RuntimeError(f"项目 patch 不存在: {patch}")

    targets = [PatchTarget("Mbed TLS 证书策略兼容", mbedtls_path, mbedtls_patch)]
    crt_bundle_text = crt_bundle_source.read_text(
        encoding="utf-8", errors="replace"
    ) if crt_bundle_source.is_file() else ""
    if "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY" in crt_bundle_text:
        targets.append(PatchTarget("IDF 6 交叉签名证书内存修复", idf_path, crt_bundle_patch))
    else:
        print("跳过 IDF 6 交叉签名证书 patch：当前 SDK 不含对应功能（IDF 5.x 正常）")

    # 先严格预检全部目标，再做任何写入，避免只应用一半。
    states: list[tuple[PatchTarget, str]] = []
    for target in targets:
        state, detail = patch_state(target)
        if state == "invalid":
            raise RuntimeError(
                "patch 既不能正向应用，也不能识别为已应用状态；"
                "拒绝 fuzzy/部分应用。\n"
                f"patch: {target.patch}\n{detail}"
            )
        states.append((target, state))

    for target, state in states:
        if state == "applied":
            print(f"patch 已经应用: {target.patch}")
            continue
        if check_only:
            print(f"patch 可应用: {target.patch}")
            continue

        result = subprocess.run(
            [
                "git",
                "-C",
                str(target.repo),
                "apply",
                "--whitespace=error",
                str(target.patch),
            ],
            check=False,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"应用 {target.label} patch 失败")
        print(f"已应用 patch: {target.patch}")


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
        apply_patches(repo_root, idf_path, args.check_only)
    except RuntimeError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
