from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from .files import STATE, UIDS, read_private, sync_directory, write_private

DIRECTORY = STATE / "gateway"
CA_LIFETIME = timedelta(days=730)
CA_WARNING = timedelta(days=30)
CA_HEALTH = timedelta(days=14)
ROTATE_HINT = "stop the instance, run `docker compose run --rm netops ca rotate`, export the new CA and update every client"

def names(name):
    try:
        address = ipaddress.ip_address(name)
        return x509.IPAddress(address), x509.IPAddress(ipaddress.ip_network(str(address) + ("/32" if address.version == 4 else "/128")))
    except ValueError:
        normalized = name.encode("idna").decode("ascii").lower()
        if not normalized or len(normalized) > 253 or any(not item or len(item) > 63 or item.startswith("-") or item.endswith("-") or not all(char.isalnum() or char == "-" for char in item) for item in normalized.split(".")):
            raise ValueError("Invalid certificate DNS name")
        return x509.DNSName(normalized), x509.DNSName(normalized)

def server_name(name):
    san, constraint = names(name)
    if not isinstance(san, x509.DNSName):
        raise ValueError("NETOPS_SERVER_NAME must be a DNS name; constrained IP certificates are unsupported by the required MCP clients. Configure client DNS or a hosts entry")
    return san, constraint

def private_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def create_ca(name, replace=False):
    _, constraint = server_name(name)
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    identity = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NetOps instance CA")])
    certificate = (x509.CertificateBuilder().subject_name(identity).issuer_name(identity).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + CA_LIFETIME).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).add_extension(x509.NameConstraints(permitted_subtrees=[constraint], excluded_subtrees=[x509.IPAddress(ipaddress.ip_network("0.0.0.0/0")), x509.IPAddress(ipaddress.ip_network("::/0"))]), critical=True).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256()))
    write_private(DIRECTORY / "ca.key", private_bytes(key), UIDS["gateway"], replace=replace)
    write_private(DIRECTORY / "ca.pem", certificate.public_bytes(serialization.Encoding.PEM), UIDS["gateway"], replace=replace)

def renew(name, force=False):
    san, _ = server_name(name)
    path = DIRECTORY / "server.pem"
    if path.exists() and not force:
        certificate = x509.load_pem_x509_certificate(read_private(path, owner=UIDS["gateway"]))
        remaining = certificate.not_valid_after_utc - datetime.now(timezone.utc)
        if remaining > timedelta(days=2):
            return False
    ca = x509.load_pem_x509_certificate(read_private(DIRECTORY / "ca.pem", owner=UIDS["gateway"]))
    key = serialization.load_pem_private_key(read_private(DIRECTORY / "ca.key", owner=UIDS["gateway"]), password=None)
    key_path = DIRECTORY / "server.key"
    leaf_key = serialization.load_pem_private_key(read_private(key_path, owner=UIDS["gateway"]), password=None) if key_path.exists() else ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    if ca.not_valid_after_utc <= now + timedelta(days=7):
        raise ValueError("Instance CA expires within 7 days and cannot renew the server certificate; " + ROTATE_HINT)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=7)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([san]), critical=False).add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True).sign(key, hashes.SHA256()))
    if not key_path.exists():
        write_private(key_path, private_bytes(leaf_key), UIDS["gateway"])
    write_private(DIRECTORY / "server.pem", leaf.public_bytes(serialization.Encoding.PEM), UIDS["gateway"], replace=True)
    return True

def instance_ca():
    return x509.load_pem_x509_certificate(read_private(DIRECTORY / "ca.pem", owner=UIDS["gateway"]))

def _public(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

def verify_pairs():
    try:
        ca = instance_ca()
        ca_key = serialization.load_pem_private_key(read_private(DIRECTORY / "ca.key", owner=UIDS["gateway"]), password=None)
        leaf = x509.load_pem_x509_certificate(read_private(DIRECTORY / "server.pem", owner=UIDS["gateway"]))
        leaf_key = serialization.load_pem_private_key(read_private(DIRECTORY / "server.key", owner=UIDS["gateway"]), password=None)
        consistent = (_public(ca_key) == ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                      and _public(leaf_key) == leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        if consistent:
            leaf.verify_directly_issued_by(ca)
    except Exception:
        consistent = False
    if not consistent:
        raise ValueError("Instance CA or server certificate files are missing or do not match, for example after an interrupted CA rotation; " + ROTATE_HINT)

def ca_fingerprint(certificate=None):
    certificate = certificate or instance_ca()
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()

def ca_remaining(now=None):
    return instance_ca().not_valid_after_utc - (now or datetime.now(timezone.utc))

def ca_notice(now=None):
    try:
        certificate = instance_ca()
    except Exception:
        return "Instance CA is missing or unreadable; " + ROTATE_HINT + ".", timedelta(0)
    remaining = certificate.not_valid_after_utc - (now or datetime.now(timezone.utc))
    if remaining <= timedelta(0):
        return "Instance CA expired on " + certificate.not_valid_after_utc.strftime("%Y-%m-%d") + "; " + ROTATE_HINT + ".", remaining
    text = "Instance CA valid until " + certificate.not_valid_after_utc.strftime("%Y-%m-%d") + " (" + str(remaining.days) + " days)."
    if remaining <= CA_WARNING:
        text += " Rotate it now: " + ROTATE_HINT + "."
    return text, remaining

def rotate_ca(name):
    server_name(name)
    retired = DIRECTORY / ("retired-ca-" + str(time.time_ns()))
    retired.mkdir(mode=0o700)
    for item in ("ca.pem", "ca.key", "server.pem", "server.key"):
        source = DIRECTORY / item
        if source.exists():
            write_private(retired / item, read_private(source, owner=UIDS["gateway"]), UIDS["gateway"])
    sync_directory(retired)
    sync_directory(DIRECTORY)
    (DIRECTORY / "server.key").unlink(missing_ok=True)
    sync_directory(DIRECTORY)
    create_ca(name, replace=True)
    renew(name, force=True)
    certificate = instance_ca()
    return ca_fingerprint(certificate), certificate.not_valid_after_utc, retired.name
