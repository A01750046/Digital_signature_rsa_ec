# Firma Digital con RSA y ECC - Versión corregida y visual elegante Juve
import streamlit as st
import base64
import csv
import os
import hashlib
import boto3
from io import StringIO, BytesIO
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

BUCKET_NAME = "firma-digital-mako"
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
)

def s3_download(key):
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=key)
        return response['Body'].read()
    except:
        return None

def s3_upload(key, content_bytes):
    s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=content_bytes)

USUARIOS_CSV = 'usuarios.csv'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def cargar_usuarios():
    data = s3_download(USUARIOS_CSV)
    if not data:
        return []
    f = StringIO(data.decode('utf-8'))
    return list(csv.DictReader(f))

def guardar_usuarios(rows):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["usuario", "contrasena"])
    writer.writeheader()
    writer.writerows(rows)
    s3_upload(USUARIOS_CSV, output.getvalue().encode('utf-8'))

def crear_usuario(usuario, contrasena):
    usuarios = cargar_usuarios()
    if any(u['usuario'] == usuario for u in usuarios):
        return False
    usuarios.append({"usuario": usuario, "contrasena": hash_password(contrasena)})
    guardar_usuarios(usuarios)
    return True

def verificar_usuario(usuario, contrasena):
    usuarios = cargar_usuarios()
    return any(u['usuario'] == usuario and u['contrasena'] == hash_password(contrasena) for u in usuarios)

def path_llaves(usuario, tipo):
    return f"llaves_{tipo}_{usuario}.csv"

def generar_llaves_y_guardar_csv(usuario, tipo):
    tipo = tipo.lower()
    if tipo == "rsa":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())

    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["tipo", "clave"])
    writer.writerow(["private_key", base64.b64encode(private_bytes).decode()])
    writer.writerow(["public_key", base64.b64encode(public_bytes).decode()])

    s3_upload(path_llaves(usuario, tipo), output.getvalue().encode())
    return private_key, public_key

def cargar_llaves_desde_csv(usuario, tipo):
    tipo = tipo.lower()
    data = s3_download(path_llaves(usuario, tipo))
    f = StringIO(data.decode())
    reader = csv.DictReader(f)
    claves = {row['tipo']: row['clave'] for row in reader}
    private_key = serialization.load_pem_private_key(
        base64.b64decode(claves['private_key']), password=None)
    public_key = serialization.load_pem_public_key(
        base64.b64decode(claves['public_key']))
    return private_key, public_key

def firmar_archivo(file_bytes, private_key, tipo):
    tipo = tipo.lower()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_bytes)
    hashed_data = digest.finalize()

    if tipo == "rsa":
        return private_key.sign(
            hashed_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            Prehashed(hashes.SHA256())
        )
    else:
        return private_key.sign(
            hashed_data,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )

def verificar_firma(file_bytes, signature, public_key, tipo):
    tipo = tipo.lower()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_bytes)
    hashed_data = digest.finalize()

    try:
        if tipo == "rsa":
            public_key.verify(
                signature,
                hashed_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                Prehashed(hashes.SHA256())
            )
        else:
            public_key.verify(signature, hashed_data, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except:
        return False

# === INTERFAZ STREAMLIT ===
col1, col2 = st.columns([4, 2])
with col1:
    st.title(" ")
    st.title("🔐 Firma Digital con RSA y Curvas Elípticas")
with col2:
    st.image("prepanet.png", width=250)

menu = st.sidebar.selectbox("Menú", ["Registrarse", "Iniciar sesión"])

tipo_display = {"RSA": "rsa", "Curvas Elípticas": "ecc"}

def get_tipo_llave_display(tipo_interno):
    for nombre, val in tipo_display.items():
        if val == tipo_interno:
            return nombre
    return tipo_interno

if menu == "Registrarse":
    st.header("Crear nuevo usuario")
    user = st.text_input("Nombre de usuario")
    pwd = st.text_input("Contraseña", type="password")
    if st.button("Registrar"):
        if crear_usuario(user, pwd):
            st.success("Usuario registrado correctamente.")
        else:
            st.error("El usuario ya existe.")

elif menu == "Iniciar sesión":
    st.header("Acceso de usuario")
    user = st.text_input("Usuario")
    pwd = st.text_input("Contraseña", type="password")
    if st.button("Iniciar sesión"):
        if verificar_usuario(user, pwd):
            st.session_state['usuario'] = user
            st.success(f"🟢 Bienvenido, {user}")
        else:
            st.error("❌ Usuario o contraseña incorrectos.")

    if 'usuario' in st.session_state:
        usuario = st.session_state['usuario']
        tipo_nombre = st.radio("Tipo de firma", list(tipo_display.keys()), horizontal=True)
        tipo_llave = tipo_display[tipo_nombre]
        path_csv = path_llaves(usuario, tipo_llave)

        if not s3_download(path_csv):
            generar_llaves_y_guardar_csv(usuario, tipo_llave)

        private_key, public_key = cargar_llaves_desde_csv(usuario, tipo_llave)

        tab1, tab2 = st.tabs(["✍️ Firmar archivo", "🔎 Verificar firma"])

        with tab1:
            st.subheader("Firma de archivos")
            file_to_sign = st.file_uploader("Sube un archivo para firmar")
            if file_to_sign and st.button("Firmar"):
                file_bytes = file_to_sign.read()
                signature = firmar_archivo(file_bytes, private_key, tipo_llave)
                st.success(f"✅ Archivo firmado correctamente con {tipo_nombre}.")
                st.download_button("Descargar firma", data=signature, file_name=file_to_sign.name + ".signature")

        with tab2:
            st.subheader("Verificación de firmas")
            file_original = st.file_uploader("Archivo original")
            file_signature = st.file_uploader("Archivo de firma (.signature)")

            usuarios = [u['usuario'] for u in cargar_usuarios()]
            firmante = st.selectbox("Selecciona el usuario que firmó el archivo", usuarios)
            tipo_nombre_verif = st.radio("Tipo de llave del firmante", list(tipo_display.keys()), horizontal=True)
            tipo_verif = tipo_display[tipo_nombre_verif]

            if firmante:
                path_firmante = path_llaves(firmante, tipo_verif)
                if s3_download(path_firmante):
                    _, public_key_firmante = cargar_llaves_desde_csv(firmante, tipo_verif)
                    if file_original and file_signature and st.button("Verificar firma"):
                        original_bytes = file_original.read()
                        signature_bytes = file_signature.read()

                        st.write("Tamaño archivo:", len(original_bytes))
                        st.write("Tamaño firma:", len(signature_bytes))

                        result = verificar_firma(original_bytes, signature_bytes, public_key_firmante, tipo_verif)
                        if result:
                            st.success(f"✅ Firma válida con {tipo_nombre_verif}. El archivo es auténtico.")
                        else:
                            st.error("❌ Firma inválida o archivo modificado.")
                else:
                    st.error("⚠️ No se encontró la llave del firmante.")
