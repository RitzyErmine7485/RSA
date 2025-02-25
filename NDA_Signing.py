from PyPDF2 import PdfReader, PdfWriter
import Crypto.Util.number
import Crypto.Random
import hashlib
import base64

E = 65537

def generar_claves():
    # Genera un par de claves RSA (pública y privada).
    global E

    p = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

    n = p * q

    phi = (p - 1) * (q - 1)

    d = Crypto.Util.number.inverse(E, phi)

    return n, d  # (clave pública, exponente), clave privada

def firmar_documento(archivo, clave_privada, clave_publica, firmante):
    # Firma el documento y agrega la firma al PDF.
    reader = PdfReader(archivo)
    texto = "".join(page.extract_text() or "" for page in reader.pages)
    hash_obj = int.from_bytes(hashlib.sha256(texto.encode()).digest(), byteorder='big')
    firma = pow(hash_obj, clave_privada, clave_publica)
    firma_b64 = base64.b64encode(firma.to_bytes((firma.bit_length() + 7) // 8, byteorder='big')).decode()
    
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({f"/firma_{firmante}": firma_b64})
    
    archivo_firmado = f"{archivo.split('.')[0]}_firmado_{firmante}.pdf"
    with open(archivo_firmado, "wb") as f:
        writer.write(f)
    
    return archivo_firmado, firma

def verificar_firma(archivo, clave_publica, firmante):
    # Verifica la firma de un firmante en el PDF.
    global E

    reader = PdfReader(archivo)
    texto = "".join(page.extract_text() or "" for page in reader.pages)
    hash_obj = hashlib.sha256(texto.encode()).digest()
    
    firma_b64 = reader.metadata.get(f"/firma_{firmante}")
    if not firma_b64:
        return False
    
    firma = int.from_bytes(base64.b64decode(firma_b64), byteorder='big')
    hash_verificado = pow(firma, E, clave_publica)
    return hash_verificado.to_bytes((hash_verificado.bit_length() + 7) // 8, byteorder='big') == hash_obj

# Generar claves
publica_alice, privada_alice = generar_claves()
publica_ac, privada_ac = generar_claves()

# Alice firma el documento
pdf_firmado_alice, firma_alice = firmar_documento("NDA.pdf", privada_alice, publica_alice, "Alice")

# La AC verifica la firma de Alice
if verificar_firma(pdf_firmado_alice, publica_alice, "Alice"):
    print("Firma de Alice válida. La AC procede a firmar.")
    pdf_firmado_ac, firma_ac = firmar_documento(pdf_firmado_alice, privada_ac, publica_ac, "AC")
    
    # Bob verifica la firma de la AC
    if verificar_firma(pdf_firmado_ac, publica_ac, "AC"):
        print("Firma de la AC válida. Documento verificado correctamente.")
    else:
        print("Firma de la AC inválida.")
else:
    print("Firma de Alice inválida.")
