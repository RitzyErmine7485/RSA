import Crypto.Random
import Crypto.Util.number
import hashlib

# Número de Fermat utilizado como exponente público en RSA
E: int = 65537

def rsa(mensaje: str):
    # Se generan las claves pública y privada para Bob
    publica_bob, privada_bob = generar_claves()

    # Se divide el mensaje en trozos de 128 caracteres
    trozos = separar_mensaje(mensaje, 128)

    # Alice cifra los hashes de cada trozo utilizando la clave pública de Bob
    mensajes_cifrados = []
    hashes_originales = []
    for trozo in trozos:
        # Se obtiene el hash SHA-256 del trozo
        hash_original = hashlib.sha256(trozo.encode('utf-8')).digest()
        hashes_originales.append(hash_original)
        
        # Se cifra el hash con la clave pública de Bob
        mensaje_cifrado = cifrar_mensaje(publica_bob, hash_original)
        mensajes_cifrados.append(mensaje_cifrado)

    # Bob descifra los mensajes usando su clave privada
    hashes_descifrados = []
    for mensaje_cifrado in mensajes_cifrados:
        hash_descifrado = descifrar_mensaje(privada_bob, publica_bob, mensaje_cifrado)
        hashes_descifrados.append(hash_descifrado)

    # Verifica si los hashes coinciden
    if confirmar_mensaje(hashes_originales, hashes_descifrados):
        print("Coincide")
    else:
        print("No coincide")

def generar_claves() -> tuple:
    global E

    # Se generan dos números primos grandes de 1024 bits
    componente_x = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    componente_y = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

    # Clave pública: producto de los primos (módulo RSA)
    clave_publica: int = componente_x * componente_y

    # Cálculo de φ(n) = (p-1) * (q-1)
    componente_z = (componente_x - 1) * (componente_y - 1)

    # Clave privada: inverso modular de E respecto a φ(n)
    clave_privada: int = Crypto.Util.number.inverse(E, componente_z)

    return clave_publica, clave_privada

def separar_mensaje(mensaje: str, tamano_trozo: int) -> list:
    # Divide el mensaje en trozos de tamaño especificado
    return [mensaje[i:i + tamano_trozo] for i in range(0, len(mensaje), tamano_trozo)]

def cifrar_mensaje(clave_publica: int, mensaje_hash: bytes) -> int:
    # Convierte el hash a un entero
    mensaje_transformado: int = int.from_bytes(mensaje_hash, byteorder='big')

    # Cifra el entero utilizando RSA con la clave pública
    mensaje_cifrado: int = pow(mensaje_transformado, E, clave_publica)
    
    return mensaje_cifrado

def descifrar_mensaje(clave_privada: int, clave_publica: int, mensaje_cifrado: int) -> bytes:
    # Descifra el mensaje usando la clave privada de Bob
    mensaje_descifrado: int = pow(mensaje_cifrado, clave_privada, clave_publica)

    # Convierte el número descifrado de nuevo a bytes (hash original)
    return mensaje_descifrado.to_bytes((mensaje_descifrado.bit_length() + 7) // 8, byteorder='big')

def confirmar_mensaje(hashes_originales: list, hashes_descifrados: list) -> bool:
    # Compara los hashes originales con los descifrados
    return hashes_originales == hashes_descifrados

# Test con un mensaje de 1050 caracteres
mensaje = "a" * 1050
rsa(mensaje)
