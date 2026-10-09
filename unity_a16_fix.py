#!/usr/bin/env python3

import argparse, json, os, re, shutil, struct, subprocess, sys, tempfile, zipfile
import urllib.request
from pathlib import Path

DRY = False
SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR / "tools"
APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar"
SIGNER_URL = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
ARCH64 = {"arm64-v8a"}


def log(msg=""):
    print(msg, flush=True)


def write_bytes(path, data):
    if not DRY:
        Path(path).write_bytes(bytes(data))


def write_text(path, text):
    if not DRY:
        Path(path).write_text(text, encoding="utf-8")


MANIFEST_ATTRS = [("allowNativeHeapPointerTagging", "false"), ("memtagMode", "off"),
                  ("gwpAsanMode", "never")]


def patch_manifest(root, debuggable=False):
    mf = root / "AndroidManifest.xml"
    if not mf.exists():
        log("[manifest] AndroidManifest.xml not found (skipped)")
        return False
    s = mf.read_text(encoding="utf-8")
    if "<application" not in s:
        log("[manifest] manifest is not decoded text (skipped)")
        return False
    changed = False
    add = [(k, v) for k, v in MANIFEST_ATTRS if f"android:{k}=" not in s]
    if add:
        attrs = " ".join(f'android:{k}="{v}"' for k, v in add)
        s = re.sub(r"<application\b", "<application " + attrs, s, count=1)
        log(f"[manifest] added to <application>: {attrs}")
        changed = True
    else:
        log("[manifest] MTE opt-out already patched")
    if debuggable:
        if re.search(r'android:debuggable="true"', s):
            log("[manifest] already debuggable")
        elif re.search(r'android:debuggable="false"', s):
            s = s.replace('android:debuggable="false"', 'android:debuggable="true"', 1)
            log('[manifest] android:debuggable false -> true')
            changed = True
        else:
            s = re.sub(r"<application\b", '<application android:debuggable="true"', s, count=1)
            log('[manifest] added android:debuggable="true" (diagnostic build)')
            changed = True
    if changed:
        write_text(mf, s)
    return changed


def _sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _exec_segments(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    if struct.unpack_from("<H", data, 18)[0] != 183:
        return None
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    segs = []
    for k in range(phnum):
        p_type, p_flags, p_off, _va, _pa, p_filesz, _ms, _al = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + k * phentsize)
        if p_type == 1 and (p_flags & 1):
            segs.append((p_off, p_filesz))
    return segs


def find_region_patches(data):
    segs = _exec_segments(data)
    if segs is None:
        return None
    patches = []
    for seg_off, seg_size in segs:
        n = seg_size // 4
        w = struct.unpack_from(f"<{n}I", data, seg_off)
        for i in range(n - 8):
            if (w[i] & 0xfffffc00) != 0xb8410400:
                continue
            if (w[i + 1] & 0xffe0fc1f) != 0x6b00001f:
                continue
            if (w[i + 2] & 0xffe0fc00) != 0x1a800000:
                continue
            if (w[i + 3] & 0xfffffc00) != 0x91000400:
                continue
            if (w[i + 4] & 0xffc0001f) != 0xf100001f:
                continue
            nslots = (w[i + 4] >> 10) & 0xfff
            if not 2 <= nslots <= 16:
                continue
            if (w[i + 5] & 0xff00001f) != 0x54000001:
                continue
            if i + 5 + _sext((w[i + 5] >> 5) & 0x7ffff, 19) != i:
                continue
            X = None
            has_lsr = False
            for back in range(1, 13):
                j = i - back
                if j < 0:
                    break
                if (w[j] & 0xffc00000) == 0xd3400000 and ((w[j] >> 16) & 0x3f) == 32 \
                        and ((w[j] >> 10) & 0x3f) == 63:
                    has_lsr = True
                if X is None and (w[j] & 0xff000000) == 0x34000000:
                    X = j + _sext((w[j] >> 5) & 0x7ffff, 19)
            if X is None or not has_lsr or not (0 <= X < n):
                continue
            if (w[X] & 0xffffffe0) != 0x2a1f03e0: 
                continue
            if (w[i + 6] & 0xfffffc1f) != 0x3100041f:
                continue
            if (w[i + 7] & 0xff00001f) != 0x54000001:
                continue
            A = None
            for m in range(i + 8, min(i + 8 + 24, n - 1)):
                is_back_cond = (w[m] & 0xff00001f) in (0x5400000b, 0x5400000d) and \
                    _sext((w[m] >> 5) & 0x7ffff, 19) < 0
                if is_back_cond and (w[m + 1] & 0xfc000000) == 0x14000000:
                    A = m + 1
                    break
            if A is None:
                continue
            new = 0x14000000 | ((X - A) & 0x3ffffff)
            addr = seg_off + A * 4
            desc = f"slots={nslots}, 'all full' -> reuse slot 0 (branch to 0x{seg_off + X * 4:x})"
            patches.append((addr, w[A], new, desc))
    return patches


def patch_libunity(root):
    changed = False
    libs = sorted(root.glob("lib/*/libunity.so"))
    if not libs:
        log("[libunity] no lib/*/libunity.so found (skipped)")
        return False
    for lib in libs:
        data = bytearray(lib.read_bytes())
        patches = find_region_patches(bytes(data))
        rel = lib.relative_to(root)
        if patches is None:
            log(f"[libunity] {rel}: not an arm64 ELF (skipped; 32-bit libs do not need this patch)")
            continue
        if not patches:
            log(f"[libunity] {rel}: allocator pattern not found "
                f"(different Unity version, or not affected)")
            continue
        todo = 0
        for addr, old, new, desc in patches:
            if old == new:
                log(f"[libunity] {rel} @0x{addr:x}: already patched")
                continue
            struct.pack_into("<I", data, addr, new)
            todo += 1
            log(f"[libunity] {rel} @0x{addr:x}: {desc}")
        if todo:
            write_bytes(lib, data)
            changed = True
    return changed


BRIDGE_CALL = re.compile(
    r"^([ \t]*)invoke-static \{([^}]*)\}, Lbitter/jnibridge/JNIBridge;->invoke"
    r"\(JLjava/lang/Class;Ljava/lang/reflect/Method;\[Ljava/lang/Object;\)Ljava/lang/Object;[ \t]*$",
    re.M)

HELPER = r'''

.method private static unityfix_invoke(JLjava/lang/Class;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    :try_start_0
    invoke-static {p0, p1, p2, p3, p4}, Lbitter/jnibridge/JNIBridge;->invoke(JLjava/lang/Class;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/NoSuchMethodError; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception v0

    invoke-virtual {p3}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "onServiceConnected"

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_check

    if-eqz p4, :cond_check

    array-length v1, p4

    const/4 v2, 0x3

    if-ne v1, v2, :cond_check

    :try_start_1
    const/4 v1, 0x2

    new-array v1, v1, [Ljava/lang/Class;

    const/4 v2, 0x0

    const-class v3, Landroid/content/ComponentName;

    aput-object v3, v1, v2

    const/4 v2, 0x1

    const-class v3, Landroid/os/IBinder;

    aput-object v3, v1, v2

    const-string v2, "onServiceConnected"

    invoke-virtual {p2, v2, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v1

    const/4 v2, 0x2

    new-array v2, v2, [Ljava/lang/Object;

    const/4 v3, 0x0

    aget-object v0, p4, v3

    aput-object v0, v2, v3

    const/4 v3, 0x1

    aget-object v0, p4, v3

    aput-object v0, v2, v3

    invoke-static {p0, p1, p2, v1, v2}, Lbitter/jnibridge/JNIBridge;->invoke(JLjava/lang/Class;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/Throwable; {:try_start_1 .. :try_end_1} :catch_1

    return-object v0

    :catch_1
    const/4 v0, 0x0

    return-object v0

    :cond_check
    invoke-virtual {p3}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object v1

    sget-object v2, Ljava/lang/Void;->TYPE:Ljava/lang/Class;

    if-eq v1, v2, :cond_null

    invoke-virtual {v1}, Ljava/lang/Class;->isPrimitive()Z

    move-result v1

    if-nez v1, :cond_throw

    :cond_null
    const/4 v0, 0x0

    return-object v0

    :cond_throw
    throw v0
.end method
'''


def patch_jnibridge(root):
    changed = False
    found = False
    for d in sorted(root.glob("smali*")):
        if not d.is_dir():
            continue
        for f in d.rglob("*.smali"):
            try:
                s = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "Lbitter/jnibridge/JNIBridge;->invoke(" not in s:
                continue
            m_cls = re.search(r"^\.class\b.*?(L[^;\s]+;)\s*$", s, re.M)
            if not m_cls or m_cls.group(1) == "Lbitter/jnibridge/JNIBridge;":
                continue
            found = True
            rel = f.relative_to(root)
            if "unityfix_invoke" in s or ".catch Ljava/lang/NoSuchMethodError;" in s:
                log(f"[jni] {rel}: already patched")
                continue
            cls = m_cls.group(1)
            n_calls = 0

            def repl(m):
                nonlocal n_calls
                regs = [r.strip() for r in m.group(2).split(",") if r.strip()]
                if len(regs) != 5:
                    return m.group(0)
                n_calls += 1
                return (f"{m.group(1)}invoke-static {{{', '.join(regs)}}}, {cls}->unityfix_invoke"
                        f"(JLjava/lang/Class;Ljava/lang/reflect/Method;[Ljava/lang/Object;)"
                        f"Ljava/lang/Object;")

            s2 = BRIDGE_CALL.sub(repl, s)
            if not n_calls:
                log(f"[jni] {rel}: unexpected JNIBridge.invoke call format (skipped)")
                continue
            write_text(f, s2.rstrip("\n") + "\n" + HELPER)
            log(f"[jni] {rel}: {n_calls} call(s) now protected against NoSuchMethodError")
            changed = True
    if not found:
        log("[jni] no class calls bitter.jnibridge.JNIBridge.invoke (skipped)")
    return changed


GMS_MARK = b"A fatal developer error has occurred"
GMS_RE = re.compile(
    r"(const/16 (v\d+), )0xa((?:[ \t]*\n[ \t]*\.line \d+)?[ \t]*\n\s*if-eq (\w+), \2, (:cond_\w+))")


def patch_gms(root):
    changed = found = False
    for d in sorted(root.glob("smali*")):
        if not d.is_dir():
            continue
        for f in d.rglob("*.smali"):
            try:
                raw = f.read_bytes()
            except OSError:
                continue
            if GMS_MARK not in raw:
                continue
            s = raw.decode("utf-8", "replace")
            rel = f.relative_to(root)
            found = True
            if "unityfix_gms" in s:
                log(f"[gms] {rel}: already patched")
                continue
            new_s, n = None, 0
            for m in GMS_RE.finditer(s):
                label = m.group(5)
                pos = s.find("\n    " + label + "\n", m.end())
                if pos != -1 and "Ljava/lang/IllegalStateException;" in s[pos:pos + 600]:
                    new_s = s[:m.start()] + m.group(1) + "-0x1" + m.group(3) + s[m.end():]
                    n = 1
                    break
            how = "status 10 (DEVELOPER_ERROR) no longer throws"
            if new_s is None:
                i = s.find(GMS_MARK.decode())
                mstart = s.rfind("\n.method ", 0, i)
                mend = s.find("\n.end method", i)
                sig = s[mstart:s.find("\n", mstart + 1)] if mstart != -1 else ""
                t = re.search(r"\n[ \t]*throw \w+", s[i:mend]) if mend != -1 else None
                if sig.rstrip().endswith(")V") and t:
                    a, b = i + t.start(), i + t.end()
                    new_s = s[:a] + "\n    return-void" + s[b:]
                    how = "fatal 'throw' replaced by return-void"
                    n = 1
            if new_s is None:
                log(f"[gms] {rel}: pattern not recognised (skipped)")
                continue
            write_text(f, new_s.rstrip("\n") + "\n\n# unityfix_gms\n")
            log(f"[gms] {rel}: {how}")
            changed = True
    if not found:
        log("[gms] no legacy Google Play services client found (skipped)")
    return changed


def need_java():
    if not shutil.which("java"):
        sys.exit("ERROR: Java was not found. Install a JRE/JDK (version 11 or newer) and run again.")


def download(url, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"  downloading {dest.name} ...")
    try:
        with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception as e:
        if dest.exists():
            dest.unlink()
        sys.exit(f"ERROR: could not download {url}\n  ({e})\n"
                 f"  Download it manually and save it as: {dest}")


def get_jar(name_glob, url, user_path=None):
    if user_path and Path(user_path).exists():
        return Path(user_path)
    for folder in (TOOLS_DIR, SCRIPT_DIR, Path.cwd()):
        found = sorted(folder.glob(name_glob)) if folder.exists() else []
        if found:
            return found[-1]
    dest = TOOLS_DIR / url.rsplit("/", 1)[1]
    download(url, dest)
    return dest


def run(cmd, what):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode:
        log(r.stdout[-3000:])
        sys.exit(f"ERROR: {what} failed (exit code {r.returncode}).")
    return r.stdout


def yml_from_json(root):
    yml, js = root / "apktool.yml", root / "apktool.json"
    if yml.exists() or not js.exists():
        return
    j = json.loads(js.read_text(encoding="utf-8"))
    q = json.dumps
    out = ["!!brut.androlib.apk.ApkInfo", f"apkFileName: {q('app.apk')}",
           f"compressionType: {str(bool(j.get('compressionType', False))).lower()}",
           "doNotCompress:"]
    out += [f"- {q(x)}" for x in j.get("doNotCompress", [])]
    out += ["isFrameworkApk: false", "packageInfo:",
            f"  forcedPackageId: {q(str(j.get('PackageInfo', {}).get('forcedPackageId', '127')))}"]
    sdk = j.get("sdkInfo", {})
    if sdk:
        out.append("sdkInfo:")
        for k in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
            if k in sdk:
                out.append(f"  {k}: {q(str(sdk[k]))}")
    out += ["sharedLibrary: false", "sparseResources: false"]
    if j.get("unknownFiles"):
        out.append("unknownFiles:")
        out += [f"  {q(k)}: {q(str(v))}" for k, v in j["unknownFiles"].items()]
    ids = j.get("UsesFramework", {}).get("ids", [1])
    out += ["usesFramework:", "  ids:"] + [f"  - {i}" for i in ids]
    out.append("version: 2.11.1")
    vi = j.get("VersionInfo", {})
    if vi:
        out.append("versionInfo:")
        for k in ("versionCode", "versionName"):
            if k in vi:
                out.append(f"  {k}: {q(str(vi[k]))}")
    write_text(yml, "\n".join(out) + "\n")
    log("[build] generated apktool.yml from apktool.json")


def sign_apk(unsigned, final, signer_jar):
    with tempfile.TemporaryDirectory() as tmp:
        run(["java", "-jar", str(signer_jar), "-a", str(unsigned), "-o", tmp,
             "--allowResign"], "signing")
        outs = sorted(Path(tmp).glob("*.apk"))
        if not outs:
            sys.exit("ERROR: the signer produced no APK.")
        shutil.move(str(outs[0]), str(final))


def inspect_abis(apk):
    abis, has_unity = {}, False
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            m = re.match(r"lib/([^/]+)/(.+\.so)$", n)
            if m:
                abis.setdefault(m.group(1), []).append(m.group(2))
                if m.group(2) == "libunity.so":
                    has_unity = True
    return abis, has_unity


def unity_version(apk):
    try:
        with zipfile.ZipFile(apk) as z:
            for n in z.namelist():
                if n.endswith("/libunity.so"):
                    m = re.search(rb"\b(\d{1,4}\.\d+\.\d+[a-z]\d+)\b", z.read(n))
                    return m.group(1).decode() if m else None
    except Exception:
        pass
    return None


def abi_check(apk):
    abis, has_unity = inspect_abis(apk)
    log(f"[abi] native libraries: {', '.join(sorted(abis)) if abis else 'none'}")
    ver = unity_version(apk)
    if has_unity:
        log("[abi] Unity engine detected" + (f" (version string {ver})" if ver else ""))
    else:
        log("[abi] WARNING: no libunity.so found - this may not be a Unity game")
    if abis and not (set(abis) & ARCH64):
        log("")
        log("=" * 70)
        log("CANNOT FIX: this APK has NO arm64-v8a (64-bit) native code.")
        log("=" * 70)
        log(f"It only ships: {', '.join(sorted(abis))}.")
        log("A 64-bit-only phone (arm64-v8a) refuses to install it")
        log("(INSTALL_FAILED_NO_MATCHING_ABIS). Renaming lib/ folders would only bypass")
        log("the installer check: the game would then crash on launch, because a 32-bit")
        log("libunity.so cannot be loaded by a 64-bit process. A real fix needs the game's")
        log("Unity project rebuilt for arm64 (old Unity 4.x never produced arm64 code).")
        log("")
        log("What you can do instead:")
        log("  - Look for a newer build of the game that includes arm64-v8a.")
        log("  - Run it in a PC Android emulator (BlueStacks / Android Studio AVD),")
        log("    which can translate 32-bit ARM or x86 code.")
        log("  - Use a device or Android version that still supports 32-bit apps.")
        return False
    return True


def apply_patches(root, a):
    if not a.skip_manifest:
        patch_manifest(root, getattr(a, "debuggable", False))
    if not a.skip_lib:
        patch_libunity(root)
    if not a.skip_jni:
        patch_jnibridge(root)
    if not a.skip_gms:
        patch_gms(root)


def pick_apk_interactively():
    folders = [SCRIPT_DIR] + ([Path.cwd()] if Path.cwd() != SCRIPT_DIR else [])
    cands = []
    for f in folders:
        for p in sorted(f.glob("*.apk")):
            if not re.search(r"(_fixed|_unsigned)\.apk$", p.name, re.I):
                cands.append(p)
    log("=" * 70)
    log(" unity_a16_fix - Unity <=2017 fixer for Android 14-16")
    log("=" * 70)
    log(f"Put the APK in this folder: {SCRIPT_DIR}")
    if cands:
        log("APK files found here:")
        for i, p in enumerate(cands, 1):
            log(f"  [{i}] {p.name}")
    else:
        log("(no .apk files found in this folder yet)")
    while True:
        default = f" [Enter = {cands[0].name}]" if len(cands) == 1 else ""
        try:
            ans = input(f"\nAPK file name (or number){default}: ").strip().strip('"')
        except EOFError:
            sys.exit("No input.")
        if not ans and len(cands) == 1:
            return cands[0]
        if not ans:
            continue
        if ans.isdigit() and 1 <= int(ans) <= len(cands):
            return cands[int(ans) - 1]
        for f in folders:
            for name in (ans, ans + ".apk"):
                if (f / name).is_file():
                    return f / name
        log(f"  '{ans}' was not found in {SCRIPT_DIR}. Try again.")


def process_apk(apk, a):
    log(f"\nInput: {apk.name}")
    if not abi_check(apk):
        return 2
    need_java()
    log("\n[tools] checking apktool and signer ...")
    apktool = get_jar("apktool*.jar", APKTOOL_URL, a.apktool)
    signer = None if a.no_sign else get_jar("uber-apk-signer*.jar", SIGNER_URL)
    if a.out:
        out = Path(a.out)
    else:
        suffix = "_unsigned.apk" if a.no_sign else ("_debug.apk" if a.debuggable else "_fixed.apk")
        out = apk.with_name(apk.stem + suffix)
    with tempfile.TemporaryDirectory() as tmp:
        work, built = Path(tmp) / "dec", Path(tmp) / "built.apk"
        log("\n[1/4] decoding APK (this can take a minute) ...")
        run(["java", "-jar", str(apktool), "d", "-f", "-o", str(work), str(apk)], "apktool decode")
        log("[2/4] applying patches ...")
        apply_patches(work, a)
        log("[3/4] rebuilding APK ...")
        run(["java", "-jar", str(apktool), "b", str(work), "-o", str(built)], "apktool build")
        if signer:
            log("[4/4] zip-aligning and signing ...")
            sign_apk(built, out, signer)
        else:
            shutil.copy(built, out)
            log("[4/4] signing skipped (--no-sign)")
    log("\n" + "=" * 70)
    log(f"DONE: {out}")
    log("=" * 70)
    log("Next steps:")
    log("  1. Uninstall the original game (the signature is different).")
    log(f"  2. Install {out.name} (copy it to the phone, or: adb install \"{out}\").")
    if signer:
        log("  (Signed with the uber-apk-signer debug key - fine for sideloading.)")
    return 0


def main():
    global DRY
    ap = argparse.ArgumentParser(description="One-click Unity <=2017 fixer for Android 14-16")
    ap.add_argument("input", nargs="?", help=".apk file or decoded apktool folder (optional)")
    ap.add_argument("--build", action="store_true", help="folder mode: also build the APK")
    ap.add_argument("--apktool", help="path to apktool.jar")
    ap.add_argument("--out")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-sign", action="store_true")
    ap.add_argument("--skip-manifest", action="store_true")
    ap.add_argument("--skip-lib", action="store_true")
    ap.add_argument("--skip-jni", action="store_true")
    ap.add_argument("--skip-gms", action="store_true")
    ap.add_argument("--debuggable", action="store_true",
                    help="diagnostic build: android:debuggable=true so 'run-as' can read the app's data")
    a = ap.parse_args()
    DRY = a.dry_run
    interactive = a.input is None
    code = 0
    try:
        src = pick_apk_interactively() if interactive else Path(a.input)
        if not src.exists():
            sys.exit(f"Not found: {src}")
        if src.is_file() and src.suffix.lower() == ".apk":
            if DRY:
                sys.exit("--dry-run only works on a decoded folder")
            code = process_apk(src, a)
        elif src.is_dir():
            apply_patches(src, a)
            if DRY:
                log("\n(dry-run: nothing was written)")
            elif a.build:
                need_java()
                apktool = get_jar("apktool*.jar", APKTOOL_URL, a.apktool)
                yml_from_json(src)
                built = src.with_name(src.name + "_unsigned.apk")
                log("[build] building ...")
                run(["java", "-jar", str(apktool), "b", str(src), "-o", str(built)], "apktool build")
                if a.no_sign:
                    log(f"\nDONE (unsigned): {built}")
                else:
                    out = Path(a.out) if a.out else src.with_name(src.name + "_fixed.apk")
                    sign_apk(built, out, get_jar("uber-apk-signer*.jar", SIGNER_URL))
                    built.unlink()
                    log(f"\nDONE: {out}")
            else:
                log("\nDone. Rebuild and sign the APK with your usual tool (or re-run with --build).")
        else:
            sys.exit("Input must be an .apk file or a decoded apktool folder.")
    except SystemExit as e:
        if interactive and e.code not in (None, 0):
            if isinstance(e.code, str):
                print(e.code)
            _pause(interactive)
            sys.exit(1)
        raise
    _pause(interactive)
    sys.exit(code)


def _pause(interactive):
    if interactive and sys.stdin.isatty():
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
