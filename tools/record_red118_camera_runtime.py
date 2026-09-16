#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STOCK_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"
CHROMATIX_PREFIXES = (
    "libchromatix_imx268_main_",
    "libchromatix_imx268_sub_",
    "libchromatix_imx380_main_",
    "libchromatix_imx380_sub_",
)
SUPPORT_PATHS = {
    "vendor/firmware/cpp_firmware_v1_12_0.fw",
    "vendor/lib/libjpegdhw.so",
    "vendor/lib/libjpegdmahw.so",
    "vendor/lib/libjpegehw.so",
    "vendor/lib/libSonyIMX380PdafLibrary.so",
    "vendor/lib/libactuator_lc898219xl_main.so",
    "vendor/lib/libactuator_lc898219xl_sub.so",
    "vendor/lib/libflash_pmic.so",
    "vendor/lib/libmmcamera_m24c64s_main_eeprom.so",
    "vendor/lib/libmmcamera_m24c64s_sub_eeprom.so",
    "vendor/lib/libmmcamera_paaf_lib.so",
    "vendor/lib/libmmcamera_ppeiscore.so",
    "vendor/lib/libmmcamera_quadracfa.so",
    "vendor/lib/libmmcamera_tintless_algo.so",
    "vendor/lib/libmmcamera_tintless_bg_pca_algo.so",
    "vendor/lib/libmmjpeg.so",
    "vendor/lib/libmmqjpeg_codec.so",
    "vendor/lib/libmmqjpegdma.so",
    "vendor/lib/libqomx_jpegdec.so",
    "vendor/lib/libqomx_jpegenc.so",
    "vendor/lib/libqomx_jpegenc_pipe.so",
    "vendor/lib/libremosaic_daemon.so",
}
ISP_MODULES = {
    "libmmcamera_isp_bpc48.so",
    "libmmcamera_isp_cac47.so",
    "libmmcamera_isp_chroma_enhan40.so",
    "libmmcamera_isp_chroma_suppress40.so",
    "libmmcamera_isp_clamp_encoder40.so",
    "libmmcamera_isp_clamp_video40.so",
    "libmmcamera_isp_clamp_viewfinder40.so",
    "libmmcamera_isp_color_correct46.so",
    "libmmcamera_isp_color_xform_encoder46.so",
    "libmmcamera_isp_color_xform_video46.so",
    "libmmcamera_isp_color_xform_viewfinder46.so",
    "libmmcamera_isp_cs_stats46.so",
    "libmmcamera_isp_demosaic48.so",
    "libmmcamera_isp_demux48.so",
    "libmmcamera_isp_fovcrop_encoder46.so",
    "libmmcamera_isp_fovcrop_video46.so",
    "libmmcamera_isp_fovcrop_viewfinder46.so",
    "libmmcamera_isp_gamma44.so",
    "libmmcamera_isp_gic48.so",
    "libmmcamera_isp_gtm46.so",
    "libmmcamera_isp_hdr48.so",
    "libmmcamera_isp_hdr_be_stats46.so",
    "libmmcamera_isp_hdr_bhist_stats44.so",
    "libmmcamera_isp_ihist_stats46.so",
    "libmmcamera_isp_linearization40.so",
    "libmmcamera_isp_ltm47.so",
    "libmmcamera_isp_mce40.so",
    "libmmcamera_isp_mesh_rolloff44.so",
    "libmmcamera_isp_pdaf48.so",
    "libmmcamera_isp_pedestal_correct46.so",
    "libmmcamera_isp_rs_stats46.so",
    "libmmcamera_isp_scaler_encoder46.so",
    "libmmcamera_isp_scaler_video46.so",
    "libmmcamera_isp_scaler_viewfinder46.so",
    "libmmcamera_isp_sce40.so",
    "libmmcamera_isp_snr47.so",
}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, data: dict) -> None:
    (ROOT / name).write_text(
        json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def camera_runtime_paths() -> set[str]:
    library_dir = ROOT / "proprietary" / "vendor" / "lib"
    chromatix = {
        f"vendor/lib/{path.name}"
        for path in library_dir.glob("libchromatix_*.so")
        if path.name.startswith(CHROMATIX_PREFIXES)
    }
    if len(chromatix) != 138:
        raise SystemExit(f"expected 138 production chromatix files, found {len(chromatix)}")
    if len(ISP_MODULES) != 36:
        raise SystemExit(f"expected 36 runtime ISP modules, found {len(ISP_MODULES)}")
    paths = chromatix | SUPPORT_PATHS | {
        f"vendor/lib/{name}" for name in ISP_MODULES
    }
    if len(paths) != 196:
        raise SystemExit(f"expected 196 camera runtime files, found {len(paths)}")
    return paths


def identity(path: str) -> dict:
    file_path = ROOT / "proprietary" / path
    if not file_path.is_file():
        raise SystemExit(f"missing RED .118 camera runtime file: {path}")
    data = file_path.read_bytes()
    return {
        "tier": "P1",
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def record_manifest(paths: set[str]) -> tuple[dict, Counter]:
    manifest = load_json("proprietary-manifest.json")
    if manifest["canonical_stock"]["sha256"] != STOCK_SHA256:
        raise SystemExit("camera runtime source authority is not RED stock .118")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for path in sorted(paths):
        expected = identity(path)
        current = by_path.get(path)
        if current is not None and current != expected:
            raise SystemExit(f"camera runtime manifest identity mismatch: {path}")
        by_path[path] = expected
    manifest["files"] = sorted(
        by_path.values(), key=lambda entry: (entry["tier"], entry["path"])
    )
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)
    return manifest, counts


def record_proprietary_list(paths: set[str]) -> None:
    list_path = ROOT / "proprietary-files.txt"
    lines = list_path.read_text(encoding="utf-8").splitlines()
    selected = {
        line.strip().lstrip("-").split("|", 1)[0].split(";", 1)[0].split(":", 1)[0]
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = sorted(paths - selected)
    if missing:
        lines.extend(("", "# RED .118 production camera runtime closure", *missing))
        list_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def record_audits(manifest: dict, counts: Counter) -> None:
    total = len(manifest["files"])
    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    source_lock = load_json("SOURCE_LOCK.json")
    source_lock["selected_files"] = total
    source_lock.setdefault("android15_contract", {})[
        "red118_camera_runtime_files"
    ] = 196
    write_json("SOURCE_LOCK.json", source_lock)

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": total,
            "p0": counts.get("P0", 0),
            "p1": counts.get("P1", 0),
            "p2": counts.get("P2", 0),
            "selected_bytes": selected_bytes,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = manifest["counts"]
    note = (
        "RED .118 production camera runtime closure retains 138 tuning libraries "
        "and 58 sensor, ISP, image-processing, JPEG, flash, and firmware files selected "
        "from the four production XMLs and captured HAL load failures; device "
        "runtime validation remains required."
    )
    notes = [
        current
        for current in tree_audit.get("notes", [])
        if not current.startswith(
            "RED .118 production camera runtime closure retains"
        )
    ]
    notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)


def main() -> int:
    paths = camera_runtime_paths()
    manifest, counts = record_manifest(paths)
    record_proprietary_list(paths)
    record_audits(manifest, counts)
    print(
        f"Recorded {len(paths)} RED .118 camera runtime files; "
        f"selected total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
