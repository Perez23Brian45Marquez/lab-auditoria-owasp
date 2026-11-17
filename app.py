import os
import psycopg2
from flask import Flask, request, jsonify, make_response
from markupsafe import escape

app = Flask(__name__)


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        user=os.getenv("DB_USER", "devuser"),
        password=os.getenv("DB_PASSWORD", "devpassword123"),
        dbname=os.getenv("DB_NAME", "banco_dev")
    )


# Vulnerabilidad 1: Inyección SQL y XSS Reflejado en búsqueda
@app.route('/api/socios/buscar', methods=['GET'])
def buscar_socio():
    termino = request.args.get('q', '')
    conn = get_connection()
    cur = conn.cursor()
    # REMEDIADO (SQLi): consulta parametrizada con parámetro posicional %s
    query = "SELECT id, username, nombre_completo, saldo FROM usuarios WHERE nombre_completo ILIKE %s;"
    try:
        cur.execute(query, (f"%{termino}%",))
        filas = cur.fetchall()
        cur.close()
        conn.close()
        resultados = [{"id": f[0], "username": f[1], "nombre": f[2], "saldo": float(f[3])} for f in filas]

        # REMEDIADO (XSS Reflejado): sin HTML manual y con la entrada escapada
        mensaje = f"Resultados obtenidos para el criterio: {escape(termino)}"
        return make_response(jsonify({"filtro": mensaje, "data": resultados}), 200)
    except Exception as e:
        # Fuga de información técnica
        return jsonify({"error_tecnico": str(e)}), 500


# Vulnerabilidad 2: BOLA / IDOR
@app.route('/api/socios/<int:usuario_id>/perfil', methods=['GET'])
def ver_perfil(usuario_id):
    # REMEDIADO (BOLA): identidad simulada mediante la cabecera X-User-Id
    try:
        solicitante_id = int(request.headers.get('X-User-Id', ''))
    except ValueError:
        return jsonify({"mensaje": "Identidad requerida"}), 401

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT rol FROM usuarios WHERE id = %s;", (solicitante_id,))
    quien = cur.fetchone()
    if not quien:
        cur.close()
        conn.close()
        return jsonify({"mensaje": "Identidad inválida"}), 401

    # Solo el propio usuario o un administrador puede ver un perfil
    if solicitante_id != usuario_id and quien[0] != 'admin':
        cur.close()
        conn.close()
        return jsonify({"mensaje": "Acceso denegado"}), 403

    cur.execute("SELECT id, username, nombre_completo, ci, saldo, rol FROM usuarios WHERE id = %s;", (usuario_id,))
    u = cur.fetchone()
    cur.close()
    conn.close()

    if not u:
        return jsonify({"mensaje": "Usuario no encontrado"}), 404

    return jsonify({
        "id": u[0],
        "username": u[1],
        "nombre": u[2],
        "ci": u[3],
        "saldo": float(u[4]),
        "rol": u[5]
    }), 200


# Vulnerabilidad 3: XSS Almacenado
@app.route('/api/comentarios', methods=['GET', 'POST'])
def comentarios():
    conn = get_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        autor = str(data.get('autor', 'Anonimo')).strip()
        mensaje = str(data.get('mensaje', '')).strip()
        # REMEDIADO: validación de longitud (evita el error 500 por VARCHAR(50))
        if not mensaje or len(autor) > 50 or len(mensaje) > 500:
            cur.close()
            conn.close()
            return jsonify({"error": "Datos inválidos"}), 400
        cur.execute("INSERT INTO comentarios (autor, mensaje) VALUES (%s, %s);", (autor, mensaje))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "comentario registrado"}), 201
    else:
        cur.execute("SELECT autor, mensaje FROM comentarios ORDER BY id DESC;")
        items = cur.fetchall()
        cur.close()
        conn.close()
        # REMEDIADO (XSS Almacenado): escape contextual al devolver los datos
        return jsonify([{"autor": str(escape(i[0])), "mensaje": str(escape(i[1]))} for i in items]), 200


# Vulnerabilidad 4: Ausencia de cabeceras de seguridad y fuga de servidor
@app.after_request
def aplicar_cabeceras(response):
    # FALLA: se expone el software del servidor y no hay CSP, HSTS ni nosniff
    response.headers['Server'] = 'Flask-Development-Server/3.0.0 (Ubuntu-Python3.11)'
    response.headers['X-Powered-By'] = 'Python-Flask-WSGI'
    return response


if __name__ == '__main__':
    # FALLA: debug=True expone la consola interactiva en caso de excepción
    app.run(host='0.0.0.0', port=5000, debug=True)