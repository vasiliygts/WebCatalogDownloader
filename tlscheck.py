#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Діагностика TLS-ланцюжка. Запуск:  python tlscheck.py elhacker.info [порт]"""
import ssl, socket, sys, os, tempfile, datetime

host = sys.argv[1] if len(sys.argv) > 1 else "elhacker.info"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

print(f"=== {host}:{port} ===")
print(f"Python {sys.version.split()[0]}  OpenSSL {ssl.OPENSSL_VERSION}")

def parse_date(s):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None

def decode_cert(der):
    """DER-байти → dict (subject/issuer/notAfter/…), лише stdlib."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

# --- крок 1: без перевірки, дивимось що віддає сервер
raw = ssl.create_default_context()
raw.check_hostname = False
raw.verify_mode = ssl.CERT_NONE
try:
    with socket.create_connection((host, port), 15) as s:
        with raw.wrap_socket(s, server_hostname=host) as ts:
            print(f"\nПротокол: {ts.version()}   Шифр: {ts.cipher()[0]}")
            ders = []
            getch = getattr(ts, "get_unverified_chain", None)
            if getch:                                       # Python 3.10+
                for c in (getch() or []):
                    ders.append(c if isinstance(c, bytes) else c.public_bytes())
            if not ders:
                bin_cert = ts.getpeercert(binary_form=True)
                if bin_cert:
                    ders = [bin_cert]
            if ders:
                print(f"\nСервер надіслав сертифікатів: {len(ders)}"
                      + ("" if getch else "  (лише листовий — старий Python)"))
                now = datetime.datetime.now()
                for i, der in enumerate(ders):
                    try:
                        info = decode_cert(der)
                    except Exception as e:
                        print(f"  [{i}] (не вдалось розібрати: {e})")
                        continue
                    subj = dict(x[0] for x in info.get("subject", ()))
                    iss = dict(x[0] for x in info.get("issuer", ()))
                    na = info.get("notAfter", "?")
                    d = parse_date(na)
                    mark = ""
                    if d:
                        left = (d - now).days
                        mark = (f"  ← ПРОСТРОЧЕНИЙ {abs(left)} дн. тому" if left < 0
                                else f"  ({left} дн. лишилось)")
                    print(f"  [{i}] CN={subj.get('commonName','?')}")
                    print(f"      видав : {iss.get('commonName','?')}")
                    print(f"      до    : {na}{mark}")
            else:
                print("\nСервер не надіслав жодного сертифіката (?).")
except Exception as e:
    print(f"\nНавіть без перевірки не з'єдналось: {type(e).__name__}: {e}")
    sys.exit(1)

# --- крок 2: штатна перевірка
print("\n--- перевірка системним сховищем ---")
try:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), 15) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ts:
            c = ts.getpeercert()
            print(f"OK. Дійсний до {c.get('notAfter')}")
except ssl.SSLCertVerificationError as e:
    print(f"НЕ ПРОЙДЕНА: {e.verify_message} (код {e.verify_code})")
except Exception as e:
    print(f"{type(e).__name__}: {e}")

# --- крок 3: перевірка через certifi
print("\n--- перевірка сховищем certifi ---")
try:
    import certifi
    ctx = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((host, port), 15) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ts:
            print(f"OK через certifi ({certifi.where()})")
            print("→ Достатньо pip install --upgrade certifi, програма підхопить сама.")
except ImportError:
    print("certifi не встановлено:  pip install certifi")
except ssl.SSLCertVerificationError as e:
    print(f"НЕ ПРОЙДЕНА і з certifi: {e.verify_message}")
    print("→ Проблема на боці сервера, не у твоєму сховищі.")
except Exception as e:
    print(f"{type(e).__name__}: {e}")
