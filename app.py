# 1. IMPORTACIONES
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
import datetime
from collections import defaultdict
import pytz 
from functools import wraps
from sqlalchemy import func
from datetime import timedelta
import os
import json





# 2. CONFIGURACIÓN DE LA APP
app = Flask(__name__)
'''app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///picking_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Es importante tener una secret_key para que los mensajes 'flash' funcionen
app.config['SECRET_KEY'] = 'una-clave-secreta-muy-dificil-de-adivinar' 
app.config['API_SECRET_KEY'] = 'MI_CLAVE_SUPER_SECRETA_12345'''

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///picking_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una-clave-secreta-muy-dificil-de-adivinar')
app.config['API_SECRET_KEY'] = os.environ.get('API_SECRET_KEY', 'MI_CLAVE_SUPER_SECRETA_12345')

db = SQLAlchemy(app)

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # La ruta a la que se redirige si un usuario no logueado intenta acceder a una página protegida
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."
login_manager.login_message_category = "error" # Categoría para mensajes flash

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Se requiere rol de administrador para acceder a esta página.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- FILTRO PERSONALIZADO PARA FECHAS ---
@app.template_filter('localtime')
def to_localtime_filter(utc_datetime):
    """
    Convierte una fecha y hora de UTC a la zona horaria de Costa Rica.
    Uso en Jinja2 (HTML): {{ una_fecha_utc | localtime }}
    """
    if not utc_datetime:
        return ""
    
    local_tz = pytz.timezone('America/Costa_Rica')
    local_dt = utc_datetime.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_dt.strftime('%d-%m-%Y %H:%M:%S')




# 3. MODELOS DE LA BASE DE DATOS
class LotePicking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    estado = db.Column(db.String(20), nullable=False, default='ACTIVO') # ACTIVO, COMPLETADO
    ordenes = db.relationship('Orden', backref='lote', lazy=True)

    # --- NUEVO CAMPO DE ASIGNACIÓN ---
    # Le decimos a la BD que si se borra el usuario, ponga este campo en NULL.
    operario_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    # ...
    # Creamos una relación para poder acceder al objeto User completo desde el lote.
    # Ej: mi_lote.operario.username
    operario = db.relationship('User', backref='lotes_asignados')
    # --- FIN DE NUEVO CAMPO ---

class Orden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero_pedido = db.Column(db.String(50), unique=True, nullable=False)
    cliente_nombre = db.Column(db.String(200), nullable=False)
    cliente_direccion = db.Column(db.String(300), nullable=True)
    
     # Estados posibles: PENDIENTE, EN_PICKING, CON_INCIDENCIA, EMPACADO, LISTO_PARA_DESPACHO, DESPACHADO, CANCELADA
    estado = db.Column(db.String(20), nullable=False, default='PENDIENTE')
    
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    lote_id = db.Column(db.Integer, db.ForeignKey('lote_picking.id'), nullable=True)
    items = db.relationship('ItemOrden', backref='orden', lazy=True, cascade="all, delete-orphan")
    
    # --- TIMESTAMPS DE PROCESOS ---
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    fecha_inicio_picking = db.Column(db.DateTime, nullable=True) # Cuando se asigna a un lote
    fecha_fin_picking = db.Column(db.DateTime, nullable=True)    # Cuando el lote se completa
    fecha_fin_packing = db.Column(db.DateTime, nullable=True)    # Cuando se finaliza el packing
    fecha_despacho = db.Column(db.DateTime, nullable=True)       # Cuando se despacha
    # --- FIN DE TIMESTAMPS ---
    
     # --- NUEVO CAMPO PARA TRAZABILIDAD DE PACKING ---
    packer_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    packer = db.relationship('User', foreign_keys=[packer_id])
    # --- FIN DE NUEVO CAMPO ---
    
    # --- NUEVO CAMPO PARA GESTIÓN DE CANCELACIÓN ---
    # Lo usaremos para que el operario pueda "marcar como leída" la cancelación.
    devolucion_confirmada = db.Column(db.Boolean, default=False, nullable=False)
    # --- FIN DE NUEVO CAMPO ---

    def __repr__(self):
        return f'<Orden {self.numero_pedido}>'

# Añadimos el nuevo modelo User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='operario') # Roles: operario, admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    # --- NUEVOS CAMPOS PARA DESPACHO ---
    transportista = db.Column(db.String(100), nullable=True)
    numero_seguimiento = db.Column(db.String(100), nullable=True)
    fecha_despacho = db.Column(db.DateTime, nullable=True)
    # --- FIN DE NUEVOS CAMPOS ---

    def __repr__(self):
        return f'<Orden {self.numero_pedido}>'

class ItemOrden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id'), nullable=False)
    codigo_articulo = db.Column(db.String(100), nullable=False)
    descripcion_articulo = db.Column(db.String(300), nullable=False)
    cantidad_solicitada = db.Column(db.Integer, nullable=False)
    cantidad_recogida = db.Column(db.Integer, nullable=False, default=0)

    # --- NUEVOS CAMPOS PARA INCIDENCIAS ---
    tiene_incidencia = db.Column(db.Boolean, default=False, nullable=False)
    tipo_incidencia = db.Column(db.String(50), nullable=True) # Ej: 'STOCK_CERO', 'DAÑADO', 'UBICACION_ERRONEA'
    nota_incidencia = db.Column(db.Text, nullable=True)
    # --- FIN DE NUEVOS CAMPOS ---

    def __repr__(self):
        return f'<Item {self.codigo_articulo} de Orden {self.orden_id}>'
    
# En app.py, dentro de la sección 3. MODELOS DE LA BASE DE DATOS

class IncidenciaHistorial(db.Model):
    __tablename__ = 'incidencia_historial' # Es una buena práctica definir explícitamente el nombre de la tabla

    id = db.Column(db.Integer, primary_key=True)
    
    # --- Información del Momento del Reporte ---
    fecha_reporte = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    tipo_incidencia = db.Column(db.String(50), nullable=False)
    nota_incidencia = db.Column(db.Text, nullable=True)
    
    # Guardamos una "foto" de las cantidades en el momento de la incidencia
    cantidad_solicitada_original = db.Column(db.Integer, nullable=False)
    cantidad_recogida_reportada = db.Column(db.Integer, nullable=False)
    
    # --- Relaciones para saber QUÉ y QUIÉN Reportó ---
    # Ligado al ItemOrden específico que tuvo el problema
    item_orden_id = db.Column(db.Integer, db.ForeignKey('item_orden.id', ondelete='CASCADE'), nullable=False)
    
    # Ligado al Usuario que reportó la incidencia
    reportado_por_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    
    # Propiedades de relación para acceder a los objetos completos
    item_orden = db.relationship('ItemOrden', backref=db.backref('historial_incidencias', cascade="all, delete-orphan"))
    reportado_por = db.relationship('User', foreign_keys=[reportado_por_id])
    
    # --- Información de la Resolución por parte del Admin/Supervisor ---
    estado_resolucion = db.Column(db.String(20), nullable=False, default='PENDIENTE') # Estados: PENDIENTE, RESUELTA
    fecha_resolucion = db.Column(db.DateTime, nullable=True)
    
    # Ligado al Usuario que resolvió la incidencia
    resuelta_por_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    nota_resolucion = db.Column(db.Text, nullable=True)
    
    # Propiedad de relación para acceder al objeto User que resolvió
    resuelta_por = db.relationship('User', foreign_keys=[resuelta_por_id])

    def __repr__(self):
        return f'<Incidencia #{self.id} para ItemOrden {self.item_orden_id}>'










# 4. RUTAS DE LA APLICACIÓN

# --- RUTAS DE AUTENTICACIÓN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Si ya está logueado, lo mandamos al dashboard
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user) # Esta función de Flask-Login registra al usuario
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required # Solo un usuario logueado puede desloguearse
def logout():
    logout_user() # Esta función de Flask-Login limpia la sesión del usuario
    flash('Ha cerrado la sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/usuario/<int:user_id>/editar', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(user_id):
    user_a_editar = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Actualizamos el rol
        user_a_editar.role = request.form.get('role')

        # Opcionalmente, actualizamos la contraseña si se proporcionó una nueva
        nueva_password = request.form.get('password')
        if nueva_password:
            user_a_editar.set_password(nueva_password)
        
        db.session.commit()
        flash(f'Usuario "{user_a_editar.username}" actualizado con éxito.', 'success')
        return redirect(url_for('gestionar_usuarios'))
    
    return render_template('editar_usuario.html', user=user_a_editar)

# En app.py, junto a las otras rutas de admin

@app.route('/admin/usuario/<int:user_id>/borrar', methods=['POST'])
@login_required
@admin_required
def borrar_usuario(user_id):
    # Un admin no puede borrarse a sí mismo
    if user_id == current_user.id:
        flash('No puedes eliminar tu propia cuenta de administrador.', 'error')
        return redirect(url_for('gestionar_usuarios'))

    user_a_borrar = User.query.get_or_404(user_id)
    username_borrado = user_a_borrar.username
    
    db.session.delete(user_a_borrar)
    db.session.commit()
    
    flash(f'Usuario "{username_borrado}" ha sido eliminado. Sus tareas ahora están sin asignar.', 'success')
    return redirect(url_for('gestionar_usuarios'))


# En app.py, reemplaza la función dashboard completa

# En app.py, reemplaza esta función completa y final

@app.route('/')
@login_required
def dashboard():
    estados_posibles = ['PENDIENTE', 'EN_PICKING', 'CON_INCIDENCIA', 'EMPACADO', 'LISTO_PARA_DESPACHO', 'DESPACHADO', 'CANCELADA']
    estado_filtro = request.args.get('estado')
    
    ordenes_canceladas_para_devolver = []

    # --- ESTRUCTURA IF/ELSE COMPLETA Y CORRECTA ---
    if current_user.role == 'admin':
        # --- LÓGICA DEL ADMIN ---
        query_base = Orden.query

        if estado_filtro:
            # Si el admin usa un filtro, se respeta.
            query_base = query_base.filter(Orden.estado == estado_filtro)
        else:
            # Vista por defecto del admin: Muestra PENDIENTE y EN_PICKING.
            # Se usa el método .in_() para filtrar por una lista de estados.
            query_base = query_base.filter(Orden.estado.in_(['PENDIENTE', 'EN_PICKING']))

    else: # Si es 'operario'
        # --- LÓGICA DEL OPERARIO ---
        # 1. Buscamos notificaciones de cancelación para el operario
        ordenes_canceladas_para_devolver = Orden.query.join(Orden.lote).filter(
            Orden.estado == 'CANCELADA',
            LotePicking.operario_id == current_user.id,
            Orden.devolucion_confirmada == False,
            Orden.items.any(ItemOrden.cantidad_recogida > 0)
        ).all()

        # 2. Buscamos las órdenes de trabajo del operario
        query_base = Orden.query # Reiniciamos la consulta base para el operario

        if estado_filtro:
            # Si el operario usa un filtro, se respeta
            query_base = query_base.filter(Orden.estado == estado_filtro)
            # Si filtra por 'EN_PICKING', solo mostramos los suyos
            if estado_filtro == 'EN_PICKING':
                 query_base = query_base.filter(Orden.lote.has(operario_id=current_user.id))
        else:
            # Vista por defecto del operario: PENDIENTES o EN_PICKING asignadas a él
            query_base = query_base.filter(
                or_(
                    Orden.estado == 'PENDIENTE',
                    Orden.lote.has(operario_id=current_user.id, estado='ACTIVO')
                )
            )
    # --- FIN DE ESTRUCTURA IF/ELSE ---

    # El resto de la función es común para ambos roles
    ordenes = query_base.order_by(Orden.fecha_creacion.desc()).all()
    operarios = User.query.filter_by(role='operario').order_by(User.username).all()
    
    return render_template('dashboard.html', 
                           ordenes=ordenes, 
                           operarios=operarios,
                           estados=estados_posibles,
                           filtro_actual=estado_filtro,
                           ordenes_a_devolver=ordenes_canceladas_para_devolver)

@app.route('/admin/usuarios', methods=['GET', 'POST'])
@login_required
@admin_required
def gestionar_usuarios():
    if request.method == 'POST':
        # Lógica para crear un nuevo usuario
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        if not all([username, password, role]):
            flash('Todos los campos son obligatorios.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe.', 'error')
        else:
            nuevo_usuario = User(username=username, role=role)
            nuevo_usuario.set_password(password)
            db.session.add(nuevo_usuario)
            db.session.commit()
            flash(f'Usuario "{username}" creado con éxito.', 'success')
            return redirect(url_for('gestionar_usuarios'))
    
    # Lógica para mostrar usuarios existentes
    usuarios = User.query.order_by(User.username).all()
    return render_template('gestionar_usuarios.html', usuarios=usuarios)

@app.route('/orden/<int:orden_id>')
@login_required
def detalle_orden(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    return render_template('detalle_orden.html', orden=orden)

@app.route('/orden/<int:orden_id>/bitacora')
@login_required
@admin_required # Solo los admins pueden ver esta vista tan detallada
def bitacora_orden(orden_id):
    from sqlalchemy.orm import joinedload, subqueryload

    # Cargamos la orden y todas sus relaciones de forma eficiente para evitar múltiples consultas
    orden = Orden.query.options(
        joinedload(Orden.lote).joinedload(LotePicking.operario), # Carga el lote y el operario de picking
        joinedload(Orden.packer), # Carga el operario de packing
        subqueryload(Orden.items).joinedload(ItemOrden.historial_incidencias) # Carga los items y su historial de incidencias
    ).get(orden_id)

    if not orden:
        flash('Orden no encontrada.', 'error')
        return redirect(url_for('reportes_y_busqueda'))

    # --- Cálculo de duraciones para la línea de tiempo ---
    duraciones = {}
    if orden.fecha_inicio_picking and orden.fecha_fin_picking:
        duraciones['picking'] = orden.fecha_fin_picking - orden.fecha_inicio_picking
    if orden.fecha_fin_picking and orden.fecha_fin_packing:
        duraciones['packing'] = orden.fecha_fin_packing - orden.fecha_fin_picking
    if orden.fecha_fin_packing and orden.fecha_despacho:
        duraciones['despacho'] = orden.fecha_despacho - orden.fecha_fin_packing
    if orden.fecha_creacion and orden.fecha_despacho:
        duraciones['total'] = orden.fecha_despacho - orden.fecha_creacion

    return render_template('bitacora_orden.html', orden=orden, duraciones=duraciones)

@app.route('/lotes/crear', methods=['POST'])
@login_required
def crear_lote():
    orden_ids = request.form.getlist('orden_id')
    if not orden_ids:
        flash('No se seleccionó ninguna orden para crear el lote.', 'error')
        return redirect(url_for('dashboard'))

    nuevo_lote = LotePicking()
    
    # --- LÓGICA DE ASIGNACIÓN FLEXIBLE ---
    if current_user.role == 'admin':
        # Si es admin, revisa si se asignó un operario desde el formulario
        operario_asignado_id = request.form.get('operario_id')
        if operario_asignado_id:
            nuevo_lote.operario_id = int(operario_asignado_id)
    else:
        # Si es operario, se auto-asigna el lote
        nuevo_lote.operario_id = current_user.id
    # --- FIN DE LÓGICA DE ASIGNACIÓN ---

    db.session.add(nuevo_lote)
    db.session.flush() # Para obtener el ID del nuevo lote

    for orden_id in orden_ids:
        orden = Orden.query.get(orden_id)
        if orden and orden.estado == 'PENDIENTE':
            orden.lote_id = nuevo_lote.id
            orden.estado = 'EN_PICKING'
            orden.fecha_inicio_picking = datetime.datetime.utcnow()
    
    db.session.commit()
    
    flash(f'Lote #{nuevo_lote.id} creado con {len(orden_ids)} órdenes.', 'success')
    return redirect(url_for('detalle_lote', lote_id=nuevo_lote.id))

@app.route('/lote/<int:lote_id>')
@login_required
def detalle_lote(lote_id):
    lote = LotePicking.query.get_or_404(lote_id)
    lista_consolidada = defaultdict(lambda: {'descripcion': '', 'solicitado': 0, 'recogido': 0})
    
    for orden in lote.ordenes:
        for item in orden.items:
            consolidado = lista_consolidada[item.codigo_articulo]
            consolidado['descripcion'] = item.descripcion_articulo
            consolidado['solicitado'] += item.cantidad_solicitada
            consolidado['recogido'] += item.cantidad_recogida
            
    lista_final = sorted(lista_consolidada.items(), key=lambda x: x[0])
    picking_completo = all(item['recogido'] >= item['solicitado'] for _, item in lista_consolidada.items()) if lista_consolidada else False

    return render_template('detalle_lote.html', lote=lote, lista_consolidada=lista_final, picking_completo=picking_completo)

@app.route('/lote/<int:lote_id>/escanear', methods=['POST'])
@login_required
def escanear_item(lote_id):
    lote = LotePicking.query.get_or_404(lote_id)
    codigo_escaneado = request.form.get('codigo_articulo', '').strip()

    if not codigo_escaneado:
        flash('No se ingresó ningún código de artículo.', 'error')
        return redirect(url_for('detalle_lote', lote_id=lote_id))

    item_a_actualizar = None
    for orden in lote.ordenes:
        for item in orden.items:
            if item.codigo_articulo == codigo_escaneado and item.cantidad_recogida < item.cantidad_solicitada:
                item_a_actualizar = item
                break
        if item_a_actualizar:
            break
            
    if item_a_actualizar:
        item_a_actualizar.cantidad_recogida += 1
        db.session.commit()
        # No usamos flash aquí para no sobrecargar la pantalla. El feedback visual es suficiente.
    else:
        flash(f'El artículo {codigo_escaneado} no es necesario o ya se recogió la cantidad completa.', 'error')

    return redirect(url_for('detalle_lote', lote_id=lote_id))

@app.route('/api/lote/<int:lote_id>/escanear', methods=['POST'])
@login_required
def api_escanear_item_lote(lote_id):
    lote = LotePicking.query.get_or_404(lote_id)
    data = request.get_json()
    codigo_escaneado = data.get('codigo_articulo', '').strip()

    if not codigo_escaneado:
        return jsonify({'success': False, 'message': 'No se ingresó ningún código.'}), 400

    item_a_actualizar = None
    # Buscamos el primer item que necesite ser recogido para este código
    for orden in lote.ordenes:
        for item in orden.items:
            if item.codigo_articulo == codigo_escaneado and item.cantidad_recogida < item.cantidad_solicitada:
                item_a_actualizar = item
                break
        if item_a_actualizar:
            break
            
    if item_a_actualizar:
        item_a_actualizar.cantidad_recogida += 1
        db.session.commit()
        
        # Después de actualizar, recalculamos el total recogido para ese código en el lote
        total_solicitado = 0
        total_recogido = 0
        for o in lote.ordenes:
            for i in o.items:
                if i.codigo_articulo == codigo_escaneado:
                    total_solicitado += i.cantidad_solicitada
                    total_recogido += i.cantidad_recogida
                    
        return jsonify({
            'success': True,
            'message': 'Artículo recogido con éxito.',
            'codigo_articulo': codigo_escaneado,
            'recogido': total_recogido,
            'solicitado': total_solicitado
        })
    else:
        return jsonify({
            'success': False, 
            'message': f'El artículo {codigo_escaneado} no es necesario o ya se recogió la cantidad completa.'
        }), 404 # 404 Not Found (o 422 Unprocessable Entity)
        
@app.route('/lote/<int:lote_id>/tomar', methods=['POST'])
@login_required
def tomar_lote(lote_id):
    # Solo los operarios pueden tomar lotes
    if current_user.role != 'operario':
        flash('Solo los operarios pueden asignarse lotes.', 'error')
        return redirect(url_for('dashboard'))

    lote = LotePicking.query.get_or_404(lote_id)

    # Doble verificación de seguridad:
    # 1. El lote debe estar activo.
    # 2. El lote no debe tener ya un operario asignado.
    if lote.estado == 'ACTIVO' and lote.operario_id is None:
        lote.operario_id = current_user.id
        db.session.commit()
        flash(f'Te has asignado el Lote #{lote.id}. ¡A trabajar!', 'success')
        # Redirigimos directamente a la pantalla de picking para empezar
        return redirect(url_for('detalle_lote', lote_id=lote.id))
    else:
        flash('Este lote ya no está disponible o ya ha sido asignado.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/api/packing/<int:orden_id>/escanear', methods=['POST'])
@login_required
def api_escanear_item_packing(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    data = request.get_json()
    codigo_escaneado = data.get('codigo_articulo', '').strip()
    
    # El conteo de packing sigue viviendo en la sesión
    session_key = f'packing_{orden_id}'
    packing_scan_counts = session.get(session_key, {})

    item_encontrado = next((item for item in orden.items if item.codigo_articulo == codigo_escaneado), None)

    if not item_encontrado:
        return jsonify({'success': False, 'message': f'El artículo {codigo_escaneado} no pertenece a esta orden.'}), 404

    current_scan_count = packing_scan_counts.get(item_encontrado.codigo_articulo, 0)
    
    if current_scan_count < item_encontrado.cantidad_solicitada:
        packing_scan_counts[item_encontrado.codigo_articulo] = current_scan_count + 1
        session[session_key] = packing_scan_counts # Guardar en la sesión
        
        return jsonify({
            'success': True,
            'message': 'Artículo verificado.',
            'codigo_articulo': item_encontrado.codigo_articulo,
            'escaneado': current_scan_count + 1,
            'solicitado': item_encontrado.cantidad_solicitada
        })
    else:
        return jsonify({
            'success': False,
            'message': f'Ya se ha escaneado la cantidad completa para {codigo_escaneado}.'
        }), 422
        

@app.route('/orden/<int:orden_id>/cancelar', methods=['POST'])
@login_required
@admin_required
def cancelar_orden(orden_id):
    orden = Orden.query.get_or_404(orden_id)

    # No se puede cancelar una orden que ya fue despachada
    if orden.estado == 'DESPACHADO':
        flash('No se puede cancelar una orden que ya ha sido despachada.', 'error')
        return redirect(request.referrer or url_for('reportes_y_busqueda'))

    # Si la orden tenía artículos ya recogidos, se debe notificar
    items_recogidos = any(item.cantidad_recogida > 0 for item in orden.items)
    
    orden.estado = 'CANCELADA'
    
    # Si estaba en un lote, no removemos la orden del lote para mantener el historial,
    # pero el lote ahora podría estar completo.
    
    db.session.commit()

    mensaje_flash = f'La orden #{orden.numero_pedido} ha sido CANCELADA.'
    if items_recogidos:
        mensaje_flash += ' ¡Atención! Se deben devolver los artículos recogidos al inventario.'
    
    flash(mensaje_flash, 'warning')
    
    # request.referrer nos devuelve a la página desde la que se hizo la petición
    return redirect(request.referrer or url_for('reportes_y_busqueda'))
        
# En app.py, añade esta nueva ruta de API

@app.route('/api/lote/<int:lote_id>/item/<codigo_articulo>/reportar-incidencia', methods=['POST'])
@login_required
def api_reportar_incidencia(lote_id, codigo_articulo):
    print(f"--- INICIANDO REPORTE DE INCIDENCIA para Lote {lote_id}, Artículo {codigo_articulo} ---")
    lote = LotePicking.query.get_or_404(lote_id)
    data = request.get_json()

    tipo_incidencia = data.get('tipo_incidencia')
    nota_incidencia = data.get('nota')
    # Cantidad que el operario dice que sí encontró en total para este código
    cantidad_encontrada_total = data.get('cantidad_recogida', 0)

    if not tipo_incidencia:
        print("!!! ERROR: No se recibió tipo_incidencia en el JSON.")
        return jsonify({'success': False, 'message': 'El tipo de incidencia es obligatorio.'}), 400

    items_afectados = []
    ordenes_afectadas_ids = set()

    for orden in lote.ordenes:
        for item in orden.items:
            if item.codigo_articulo == codigo_articulo:
                items_afectados.append(item)
                ordenes_afectadas_ids.add(item.orden_id)

    if not items_afectados:
        print(f"!!! ERROR: No se encontró el artículo {codigo_articulo} en el lote {lote_id}.")
        return jsonify({'success': False, 'message': 'Artículo no encontrado en este lote.'}), 404

    print(f"Items afectados encontrados: {len(items_afectados)}")

    # Bucle para actualizar los items y crear el historial
    for item in items_afectados:
        # 1. Actualizar el ItemOrden
        item.tiene_incidencia = True
        item.tipo_incidencia = tipo_incidencia
        item.nota_incidencia = nota_incidencia
        
        # Lógica de distribución de cantidad simplificada
        if cantidad_encontrada_total >= item.cantidad_solicitada:
            item.cantidad_recogida = item.cantidad_solicitada
            cantidad_encontrada_total -= item.cantidad_solicitada
        else:
            item.cantidad_recogida = cantidad_encontrada_total
            cantidad_encontrada_total = 0

        # 2. Crear el registro en el historial para este item específico
        print(f"-> Creando registro en IncidenciaHistorial para ItemOrden ID: {item.id}")
        historial_entry = IncidenciaHistorial(
            item_orden_id=item.id,
            reportado_por_id=current_user.id,
            tipo_incidencia=tipo_incidencia,
            nota_incidencia=nota_incidencia,
            cantidad_solicitada_original=item.cantidad_solicitada,
            cantidad_recogida_reportada=item.cantidad_recogida # Usamos la cantidad ya calculada para este item
        )
        db.session.add(historial_entry)

    # Actualizar las órdenes afectadas
    for orden_id in ordenes_afectadas_ids:
        orden_a_actualizar = Orden.query.get(orden_id)
        if orden_a_actualizar:
            print(f"-> Cambiando estado de Orden ID: {orden_id} a CON_INCIDENCIA")
            orden_a_actualizar.estado = 'CON_INCIDENCIA'

    try:
        db.session.commit()
        print("--- COMMIT EXITOSO. Incidencia guardada. ---")
        return jsonify({'success': True, 'message': 'Incidencia reportada y registrada en el historial.'})
    except Exception as e:
        db.session.rollback()
        print(f"!!! ERROR DURANTE EL COMMIT: {e}")
        return jsonify({'success': False, 'message': 'Error al guardar la incidencia en la base de datos.'}), 500



@app.route('/api/incidencias/pendientes-count')
@login_required
@admin_required
def api_incidencias_pendientes_count():
    # Contamos las incidencias únicas por orden que están pendientes de revisión.
    # Se usa .distinct() para no contar dos veces si una orden tiene multiples items con incidencia.
    count = db.session.query(func.count(Orden.id.distinct())).filter(Orden.estado == 'CON_INCIDENCIA').scalar()
    return jsonify({'pendientes': count})

@app.route('/lote/<int:lote_id>/finalizar', methods=['POST'])
@login_required
def finalizar_lote(lote_id):
    lote = LotePicking.query.get_or_404(lote_id)
    
    # --- LÓGICA DE FINALIZACIÓN CORREGIDA ---
    for orden in lote.ordenes:
        # Verificamos si algún item en esta orden tiene una incidencia activa.
        # La función any() es una forma eficiente de hacer esto.
        tiene_incidencias_activas = any(item.tiene_incidencia for item in orden.items)

        if tiene_incidencias_activas:
            # Si la orden tiene incidencias, su estado ya debería ser 'CON_INCIDENCIA'.
            # No hacemos nada con ella aquí, la dejamos para que el admin la gestione.
            # Podríamos añadir una validación extra si quisiéramos.
            pass # Explícitamente no hacemos nada.
        else:
            # Si la orden está "limpia" (sin incidencias), la enviamos a Packing.
            orden.estado = 'EMPACADO'
            orden.fecha_fin_picking = datetime.datetime.utcnow()
    
    lote.estado = 'COMPLETADO'
    db.session.commit()
    
    flash(f'¡Lote #{lote.id} completado! Las órdenes sin incidencias pasaron a EMPACADO.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/packing')
@login_required
def dashboard_packing():
    # Muestra todas las órdenes que están listas para ser empacadas
    ordenes_para_packing = Orden.query.filter_by(estado='EMPACADO').order_by(Orden.fecha_creacion.asc()).all()
    return render_template('dashboard_packing.html', ordenes=ordenes_para_packing)

@app.route('/packing/<int:orden_id>', methods=['GET', 'POST'])
@login_required
def detalle_packing(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    if orden.estado != 'EMPACADO':
        flash('Esta orden no está lista para packing.', 'error')
        return redirect(url_for('dashboard_packing'))

    session_key = f'packing_{orden_id}'

    # Lógica para la carga inicial de la página (GET)
    if request.method == 'GET':
        # Si la sesión para esta orden de packing no existe, la inicializamos.
        if session_key not in session:
            print(f"--- Inicializando sesión de packing para orden #{orden.id} ---")
            initial_counts = {}
            # Iteramos sobre los ítems de la base de datos
            for item in orden.items:
                # ¡AQUÍ ESTÁ LA MAGIA!
                # Si un ítem ya tiene su cantidad recogida completa (como los de servicio),
                # precargamos ese valor en nuestro contador de packing.
                if item.cantidad_recogida >= item.cantidad_solicitada:
                    initial_counts[item.codigo_articulo] = item.cantidad_solicitada
                    print(f"  -> Precargando ítem de servicio/completo: {item.codigo_articulo} con cantidad {item.cantidad_solicitada}")
            
            session[session_key] = initial_counts

    # El resto del código de la función (tanto para GET como para POST) se mantiene,
    # pero ahora parte de una sesión potencialmente ya inicializada.

    # --- LÓGICA DE ESCANEO (POST) ---
    if request.method == 'POST':
        codigo_escaneado = request.form.get('codigo_articulo', '').strip()
        # ... (Toda tu lógica de escaneo POST no necesita cambios) ...
        # ... (buscar item, actualizar session[session_key], etc.) ...
        packing_scan_counts = session.get(session_key, {})
        item_encontrado = next((item for item in orden.items if item.codigo_articulo == codigo_escaneado), None)
        if item_encontrado:
            current_scan_count = packing_scan_counts.get(item_encontrado.codigo_articulo, 0)
            if current_scan_count < item_encontrado.cantidad_solicitada:
                packing_scan_counts[item_encontrado.codigo_articulo] = current_scan_count + 1
                session[session_key] = packing_scan_counts
            else:
                flash(f'Ya se ha escaneado la cantidad completa para {codigo_escaneado}.', 'warning')
        else:
            flash(f'El artículo {codigo_escaneado} no pertenece a esta orden.', 'error')
        return redirect(url_for('detalle_packing', orden_id=orden_id))

    # --- LÓGICA PARA MOSTRAR LA PÁGINA (GET) ---
    packing_scan_counts = session.get(session_key, {})
    
    packing_completo = True
    for item in orden.items:
        if packing_scan_counts.get(item.codigo_articulo, 0) != item.cantidad_solicitada:
            packing_completo = False
            break

    return render_template('detalle_packing.html', orden=orden, packing_counts=packing_scan_counts, packing_completo=packing_completo)


@app.route('/packing/<int:orden_id>/finalizar', methods=['POST'])
@login_required
def finalizar_packing(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    
    # Aquí podríamos añadir una doble verificación final si fuera necesario
    
    orden.estado = 'LISTO_PARA_DESPACHO'
    orden.fecha_fin_packing = datetime.datetime.utcnow()
    orden.packer_id = current_user.id
    db.session.commit()

    # Limpiar los datos de sesión para esta orden
    session.pop(f'packing_{orden_id}', None)

    flash(f'Orden #{orden.numero_pedido} marcada como LISTA PARA DESPACHO.', 'success')
    return redirect(url_for('dashboard_packing'))




# --- ENDPOINT DE LA API (SIN CAMBIOS) ---
# Esta es la lista de codigos a procesar como recogidos pues son un servicio y no un producto fisico
CODIGOS_DE_SERVICIO = {'0356', '0357', '0358', 'PROMO', 'EMP01'}

@app.route('/api/ordenes/crear-desde-factura', methods=['POST'])
def crear_orden_desde_factura():
    # 1. Verificación de seguridad
    api_key = request.headers.get('X-API-KEY')
    if not api_key or api_key != app.config['API_SECRET_KEY']:
        return jsonify({'error': 'Acceso no autorizado.'}), 403

    # 2. Obtención y validación de datos
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No se recibieron datos JSON.'}), 400
        
    print("--- Datos recibidos en la API para crear orden ---")
    print(json.dumps(data, indent=2))

    if not all(k in data for k in ['pedido', 'cliente', 'items']) or not data['items']:
        return jsonify({'error': 'Faltan datos esenciales en el JSON (pedido, cliente o items).'}), 400

    # 3. Evitar duplicados
    if Orden.query.filter_by(numero_pedido=data['pedido']).first():
        print(f"Orden duplicada detectada y omitida: #{data['pedido']}")
        return jsonify({'mensaje': f'La orden #{data["pedido"]} ya existe y fue omitida.'}), 200

    try:
        # 4. Crear la orden principal
        nueva_orden = Orden(
            numero_pedido=data['pedido'],
            cliente_nombre=data['cliente'].get('nombre', 'N/A'),
            cliente_direccion=data['cliente'].get('direccion', 'N/A')
        )
        db.session.add(nueva_orden)
        db.session.flush()

        print(f"Orden #{nueva_orden.numero_pedido} creada con ID {nueva_orden.id}. Añadiendo {len(data['items'])} ítems...")

        # 5. Bucle para crear los ítems (CON LA LÓGICA CORREGIDA)
        for i, item_data in enumerate(data['items']):
            # --- CORRECCIÓN: Definimos las variables al principio ---
            codigo_item = item_data.get('codigo', '').strip()
            cantidad_solicitada = int(item_data.get('cantidad', 0))
            
            # Ahora la validación se hace sobre las variables ya creadas
            if not codigo_item or cantidad_solicitada <= 0:
                print(f"  -> Omitiendo ítem #{i+1} por falta de código o cantidad válida.")
                continue 

            nuevo_item = ItemOrden(
                orden_id=nueva_orden.id,
                codigo_articulo=codigo_item,
                descripcion_articulo=item_data.get('articulo', 'N/A'),
                cantidad_solicitada=cantidad_solicitada
            )

            if codigo_item in CODIGOS_DE_SERVICIO:
                nuevo_item.cantidad_recogida = cantidad_solicitada
                print(f"  -> Añadido ÍTEM DE SERVICIO: {codigo_item} (auto-completado)")
            else:
                nuevo_item.cantidad_recogida = 0
                print(f"  -> Añadido a la sesión: {codigo_item} (Cantidad: {cantidad_solicitada})")
            
            db.session.add(nuevo_item)

        # 6. Commit final
        db.session.commit()
        print("--- Commit final exitoso. Todos los ítems guardados. ---")
        return jsonify({'mensaje': 'Orden creada con éxito', 'id_orden': nueva_orden.id}), 201

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Ocurrió un error en el servidor: {str(e)}'}), 500
    

    
@app.route('/despacho')
@login_required
def dashboard_despacho():
    """Muestra el dashboard con las órdenes listas para ser despachadas."""
    ordenes_para_despacho = Orden.query.filter_by(estado='LISTO_PARA_DESPACHO').order_by(Orden.fecha_creacion.asc()).all()
    return render_template('dashboard_despacho.html', ordenes=ordenes_para_despacho)

@app.route('/despacho/<int:orden_id>', methods=['GET', 'POST'])
@login_required
def detalle_despacho(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    
    # Clave de sesión única para esta orden
    session_key = f'despacho_verificado_{orden_id}'

    # Si estamos procesando el formulario de despacho final (método POST)
    if request.method == 'POST':
        # Doble seguridad: nos aseguramos de que la orden haya sido verificada en esta sesión
        if not session.get(session_key):
            flash('Error de seguridad: La orden debe ser verificada por escaneo antes de despachar.', 'error')
            return redirect(url_for('detalle_despacho', orden_id=orden_id))

        transportista = request.form.get('transportista')
        # ... (resto de tu lógica para guardar transportista, tracking, etc.) ...
        orden.estado = 'DESPACHADO'
        db.session.commit()
        
        # Importante: Limpiamos la clave de sesión después de despachar
        session.pop(session_key, None)
        
        flash(f'¡Orden #{orden.numero_pedido} despachada con éxito!', 'success')
        return redirect(url_for('dashboard_despacho'))

    # Si estamos cargando la página (método GET)
    # Verificamos si la orden ya ha sido verificada en esta sesión
    verificado = session.get(session_key, False)
    
    return render_template('detalle_despacho.html', orden=orden, verificado=verificado)

# --- RUTA PARA REPORTES Y BÚSQUEDA ---
@app.route('/reportes', methods=['GET', 'POST'])
@login_required
@admin_required
def reportes_y_busqueda():
    orden_encontrada = None
    stats = {
        'tiempo_picking_avg': 'N/A',
        'tiempo_packing_avg': 'N/A',
        'tiempo_despacho_avg': 'N/A',
        'ordenes_hoy': 0
    }

     # --- INICIO DE LA LÓGICA DE HISTORIAL ---
    # Obtenemos el historial de la sesión; si no existe, creamos una lista vacía.
    historial_busqueda = session.get('historial_busqueda', [])
    # --- FIN DE LA LÓGICA DE HISTORIAL ---

    if request.method == 'POST':
        numero_pedido_buscado = request.form.get('numero_pedido', '').strip()
        if numero_pedido_buscado:
            orden_encontrada = Orden.query.filter(Orden.numero_pedido.ilike(f"%{numero_pedido_buscado}%")).first()
            if not orden_encontrada:
                flash(f'No se encontró ninguna orden con el número "{numero_pedido_buscado}".', 'error')
            else:
                # --- AÑADIR AL HISTORIAL SI LA BÚSQUEDA FUE EXITOSA ---
                # 1. Si el pedido ya está en el historial, lo removemos para volver a añadirlo al principio.
                if orden_encontrada.numero_pedido in historial_busqueda:
                    historial_busqueda.remove(orden_encontrada.numero_pedido)
                
                # 2. Añadimos el nuevo número de pedido al principio de la lista.
                historial_busqueda.insert(0, orden_encontrada.numero_pedido)
                
                # 3. Limitamos el historial a los últimos 5 elementos.
                session['historial_busqueda'] = historial_busqueda[:5]
                # --- FIN DE AÑADIR AL HISTORIAL ---

    # --- Cálculo de Estadísticas (se ejecuta siempre al cargar la página) ---
    try:
        # 1. Tiempos promedio de Picking
        tiempos_picking = [
            o.fecha_fin_picking - o.fecha_inicio_picking for o in Orden.query.filter(
                Orden.fecha_inicio_picking.isnot(None), 
                Orden.fecha_fin_picking.isnot(None)
            ).all()
        ]
        if tiempos_picking:
            tiempo_total_picking = sum(tiempos_picking, datetime.timedelta())
            stats['tiempo_picking_avg'] = str(tiempo_total_picking / len(tiempos_picking)).split('.')[0] # Formato H:MM:SS

        # 2. Tiempos promedio de Packing
        tiempos_packing = [
            o.fecha_fin_packing - o.fecha_fin_picking for o in Orden.query.filter(
                Orden.fecha_fin_picking.isnot(None),
                Orden.fecha_fin_packing.isnot(None)
            ).all()
        ]
        if tiempos_packing:
            tiempo_total_packing = sum(tiempos_packing, datetime.timedelta())
            stats['tiempo_packing_avg'] = str(tiempo_total_packing / len(tiempos_packing)).split('.')[0]

        # 3. Tiempos promedio "Puerta a Puerta" (Creación -> Despacho)
        tiempos_ciclo_completo = [
            o.fecha_despacho - o.fecha_creacion for o in Orden.query.filter(
                Orden.fecha_creacion.isnot(None),
                Orden.fecha_despacho.isnot(None)
            ).all()
        ]
        if tiempos_ciclo_completo:
            tiempo_total_ciclo = sum(tiempos_ciclo_completo, datetime.timedelta())
            stats['tiempo_ciclo_completo_avg'] = str(tiempo_total_ciclo / len(tiempos_ciclo_completo)).split('.')[0]

        # 4. Órdenes creadas hoy
        hoy_inicio = datetime.datetime.combine(datetime.date.today(), datetime.time.min)
        hoy_fin = datetime.datetime.combine(datetime.date.today(), datetime.time.max)
        stats['ordenes_hoy'] = Orden.query.filter(Orden.fecha_creacion.between(hoy_inicio, hoy_fin)).count()

    except Exception as e:
        print(f"Error calculando estadísticas: {e}")
        flash('Ocurrió un error al calcular las estadísticas.', 'error')

    return render_template('reportes.html', stats=stats, orden=orden_encontrada, historial=historial_busqueda)

# En app.py, reemplaza esta función completa

@app.route('/reportes/operarios')
@login_required
@admin_required
def reporte_operarios():
    # --- Lógica de Filtro de Fechas ---
    periodo = request.args.get('periodo', 'semana')
    hoy = datetime.datetime.utcnow().date()
    fecha_inicio = None
    if periodo == 'hoy':
        fecha_inicio = datetime.datetime.combine(hoy, datetime.time.min)
    elif periodo == 'mes':
        fecha_inicio = datetime.datetime(hoy.year, hoy.month, 1)
    else: # Por defecto 'semana'
        fecha_inicio = datetime.datetime.combine(hoy - timedelta(days=6), datetime.time.min)

    # --- Lógica de compatibilidad de Base de Datos ---
    dialect_name = db.engine.dialect.name
    if dialect_name == 'postgresql':
        func_diff_seconds_picking = func.extract('epoch', Orden.fecha_fin_picking) - func.extract('epoch', Orden.fecha_inicio_picking)
        func_diff_seconds_packing = func.extract('epoch', Orden.fecha_fin_packing) - func.extract('epoch', Orden.fecha_fin_picking)
    else: # SQLite
        func_diff_seconds_picking = func.strftime('%s', Orden.fecha_fin_picking) - func.strftime('%s', Orden.fecha_inicio_picking)
        func_diff_seconds_packing = func.strftime('%s', Orden.fecha_fin_packing) - func.strftime('%s', Orden.fecha_fin_picking)
    
    # --- Subconsulta 1: KPIs de PICKING ---
    kpis_picking = db.session.query(
        LotePicking.operario_id,
        func.count(LotePicking.id).label('lotes_completados'),
        func.avg(func_diff_seconds_picking).label('tiempo_prom_picking')
    ).join(LotePicking.ordenes).filter(
        LotePicking.estado == 'COMPLETADO',
        LotePicking.operario_id.isnot(None),
        Orden.fecha_fin_picking.isnot(None),
        Orden.fecha_inicio_picking.isnot(None),
        Orden.fecha_fin_picking >= fecha_inicio
    ).group_by(LotePicking.operario_id).subquery()

    # --- Subconsulta 2: KPIs de ITEMS ---
    kpis_items = db.session.query(
        LotePicking.operario_id,
        func.sum(ItemOrden.cantidad_recogida).label('items_recogidos'),
        func.count(Orden.id).label('ordenes_procesadas_picking')
    ).join(LotePicking.ordenes).join(Orden.items).filter(
        LotePicking.estado == 'COMPLETADO',
        LotePicking.operario_id.isnot(None),
        Orden.fecha_fin_picking >= fecha_inicio
    ).group_by(LotePicking.operario_id).subquery()

    # --- Subconsulta 3: KPIs de PACKING ---
    kpis_packing = db.session.query(
        Orden.packer_id,
        func.count(Orden.id).label('ordenes_empacadas'),
        func.avg(func_diff_seconds_packing).label('tiempo_prom_packing')
    ).filter(
        Orden.packer_id.isnot(None),
        Orden.fecha_fin_packing.isnot(None),
        Orden.fecha_fin_picking.isnot(None),
        Orden.fecha_fin_packing >= fecha_inicio
    ).group_by(Orden.packer_id).subquery()

    # --- Consulta Principal: Unir TODO con la tabla de Usuarios ---
    reporte_data = db.session.query(
        User,
        kpis_picking.c.lotes_completados,
        kpis_picking.c.tiempo_prom_picking,
        kpis_items.c.items_recogidos,
        kpis_packing.c.ordenes_empacadas,
        kpis_packing.c.tiempo_prom_packing
    ).outerjoin(
        kpis_picking, User.id == kpis_picking.c.operario_id
    ).outerjoin(
        kpis_items, User.id == kpis_items.c.operario_id
    ).outerjoin(
        kpis_packing, User.id == kpis_packing.c.packer_id
    ).filter(User.role == 'operario').all()

    return render_template('reporte_operarios.html', 
                           reporte_data=reporte_data,
                           periodo_actual=periodo,
                           fecha_inicio=fecha_inicio)

@app.route('/incidencias')
@login_required
@admin_required
def gestionar_incidencias():
    # Buscamos todas las órdenes que han sido marcadas con una incidencia
    ordenes_con_incidencia = Orden.query.filter_by(estado='CON_INCIDENCIA').order_by(Orden.fecha_creacion.desc()).all()
    return render_template('gestionar_incidencias.html', ordenes=ordenes_con_incidencia)

@app.route('/incidencia/<int:item_id>/resolver', methods=['POST'])
@login_required
@admin_required
def resolver_incidencia(item_id):
    item = ItemOrden.query.get_or_404(item_id)
    orden = item.orden

    # La acción es "Ajustar y Aprobar"
    # 1. La cantidad solicitada ahora es la que realmente se recogió.
    item.cantidad_solicitada = item.cantidad_recogida
    item.tiene_incidencia = False # La incidencia está resuelta
    
      # --- ACTUALIZAR EL REGISTRO HISTÓRICO ---
    # Buscamos la última incidencia PENDIENTE para este item
    incidencia_a_resolver = IncidenciaHistorial.query.filter_by(
        item_orden_id=item.id, 
        estado_resolucion='PENDIENTE'
    ).first()

    if incidencia_a_resolver:
        incidencia_a_resolver.estado_resolucion = 'RESUELTA'
        incidencia_a_resolver.fecha_resolucion = datetime.datetime.utcnow()
        incidencia_a_resolver.resuelta_por_id = current_user.id
        # Podríamos añadir un campo en el formulario para una nota de resolución
        incidencia_a_resolver.nota_resolucion = "Admin ajustó la cantidad y aprobó para packing."
    # --- FIN DE ACTUALIZACIÓN ---
    
    # 2. Verificamos si hay OTROS items con incidencia en la misma orden
    hay_otras_incidencias = any(i.tiene_incidencia for i in orden.items)

    # 3. Si no hay más incidencias en esta orden, la enviamos a Packing.
    if not hay_otras_incidencias:
        orden.estado = 'EMPACADO'
        orden.fecha_fin_picking = datetime.datetime.utcnow() # Marcamos la fecha de fin de picking
    
    db.session.commit()
    flash(f'Incidencia del artículo {item.codigo_articulo} resuelta y registrada en el historial.', 'success')
    return redirect(url_for('gestionar_incidencias'))

@app.route('/historial/incidencias')
@login_required
@admin_required
def historial_incidencias():
    # El .join() y .options() son para cargar eficientemente los datos relacionados
    # y evitar muchas consultas pequeñas a la BD (problema N+1)
    from sqlalchemy.orm import joinedload
    historial = IncidenciaHistorial.query.options(
        joinedload(IncidenciaHistorial.item_orden).joinedload(ItemOrden.orden),
        joinedload(IncidenciaHistorial.reportado_por),
        joinedload(IncidenciaHistorial.resuelta_por)
    ).order_by(IncidenciaHistorial.fecha_reporte.desc()).all()
    
    return render_template('historial_incidencias.html', historial=historial)

# En app.py, añade esta nueva ruta

@app.route('/orden/<int:orden_id>/confirmar-devolucion', methods=['POST'])
@login_required
def confirmar_devolucion(orden_id):
    # Solo el operario que la recogió puede confirmar la devolución
    orden = Orden.query.join(Orden.lote).filter(
        Orden.id == orden_id,
        LotePicking.operario_id == current_user.id
    ).first_or_404()

    orden.devolucion_confirmada = True
    db.session.commit()

    flash(f'Devolución de artículos para la orden #{orden.numero_pedido} confirmada.', 'success')
    return redirect(url_for('dashboard'))

# En app.py, añade esta nueva ruta

@app.route('/api/reportes/rendimiento-operarios')
@login_required
@admin_required
def api_reporte_rendimiento_operarios():
    try:
        # --- Lógica de Filtro de Fechas ---
        periodo = request.args.get('periodo', 'semana')
        hoy = datetime.datetime.utcnow().date()
        fecha_inicio = None
        if periodo == 'hoy':
            fecha_inicio = datetime.datetime.combine(hoy, datetime.time.min)
        elif periodo == 'mes':
            fecha_inicio = datetime.datetime(hoy.year, hoy.month, 1)
        else: # 'semana'
            fecha_inicio = datetime.datetime.combine(hoy - timedelta(days=6), datetime.time.min)

        # --- Lógica de compatibilidad de Base de Datos ---
        dialect_name = db.engine.dialect.name
        if dialect_name == 'postgresql':
            func_diff_seconds_picking = func.extract('epoch', Orden.fecha_fin_picking) - func.extract('epoch', Orden.fecha_inicio_picking)
            func_diff_seconds_packing = func.extract('epoch', Orden.fecha_fin_packing) - func.extract('epoch', Orden.fecha_fin_picking)
        else: # SQLite
            func_diff_seconds_picking = func.strftime('%s', Orden.fecha_fin_picking) - func.strftime('%s', Orden.fecha_inicio_picking)
            func_diff_seconds_packing = func.strftime('%s', Orden.fecha_fin_packing) - func.strftime('%s', Orden.fecha_fin_picking)

        # --- Subconsultas (idénticas a la otra ruta, pero autocontenidas) ---
        kpis_picking = db.session.query(
            LotePicking.operario_id,
            func.count(LotePicking.id).label('lotes_completados'),
            func.avg(func_diff_seconds_picking).label('tiempo_prom_picking')
        ).join(LotePicking.ordenes).filter(
            LotePicking.estado == 'COMPLETADO',
            LotePicking.operario_id.isnot(None),
            Orden.fecha_fin_picking.isnot(None),
            Orden.fecha_inicio_picking.isnot(None),
            Orden.fecha_fin_picking >= fecha_inicio
        ).group_by(LotePicking.operario_id).subquery()

        kpis_items = db.session.query(
            LotePicking.operario_id,
            func.sum(ItemOrden.cantidad_recogida).label('items_recogidos')
        ).join(LotePicking.ordenes).join(Orden.items).filter(
            LotePicking.estado == 'COMPLETADO',
            LotePicking.operario_id.isnot(None),
            Orden.fecha_fin_picking >= fecha_inicio
        ).group_by(LotePicking.operario_id).subquery()

        kpis_packing = db.session.query(
            Orden.packer_id,
            func.count(Orden.id).label('ordenes_empacadas'),
            func.avg(func_diff_seconds_packing).label('tiempo_prom_packing')
        ).filter(
            Orden.packer_id.isnot(None),
            Orden.fecha_fin_packing.isnot(None),
            Orden.fecha_fin_picking.isnot(None),
            Orden.fecha_fin_packing >= fecha_inicio
        ).group_by(Orden.packer_id).subquery()
        
        # --- Consulta Principal ---
        reporte_data = db.session.query(
            User,
            kpis_picking.c.lotes_completados,
            kpis_picking.c.tiempo_prom_picking,
            kpis_items.c.items_recogidos,
            kpis_packing.c.ordenes_empacadas,
            kpis_packing.c.tiempo_prom_packing
        ).outerjoin(
            kpis_picking, User.id == kpis_picking.c.operario_id
        ).outerjoin(
            kpis_items, User.id == kpis_items.c.operario_id
        ).outerjoin(
            kpis_packing, User.id == kpis_packing.c.packer_id
        ).filter(User.role == 'operario').order_by(User.username).all()
        
        # --- Procesar Datos para JSON ---
        json_data = []
        for user, lotes, tiempo_pick, items, ordenes_pack, tiempo_pack in reporte_data:
            json_data.append({
                "username": user.username,
                "lotes_completados": lotes or 0,
                "items_recogidos": items or 0,
                "ordenes_empacadas": ordenes_pack or 0,
                "tiempo_prom_picking": tiempo_pick or 0,
                "tiempo_prom_packing": tiempo_pack or 0
            })

        return jsonify(json_data)

    except Exception as e:
        print(f"Error en la API de reportes: {e}")
        return jsonify({"error": "No se pudieron generar los datos para el gráfico"}), 500

@app.route('/api/ordenes/pendientes-count')
@login_required
def api_ordenes_pendientes_count():
    # Contamos las órdenes que están en estado PENDIENTE
    count = db.session.query(func.count(Orden.id)).filter(Orden.estado == 'PENDIENTE').scalar()
    
    return jsonify({'pendientes': count})


# En app.py, añade esta nueva ruta

@app.route('/despacho/<int:orden_id>/verificar', methods=['POST'])
@login_required
def verificar_despacho(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    codigo_escaneado = request.form.get('codigo_escaneado', '').strip()

    # Comparamos el código escaneado con el número de pedido esperado
    if codigo_escaneado == orden.numero_pedido:
        # ¡Éxito! Guardamos en la sesión que esta orden ha sido verificada.
        session[f'despacho_verificado_{orden_id}'] = True
        flash('Caja correcta. Puede proceder con el despacho.', 'success')
    else:
        flash(f'¡CAJA INCORRECTA! Se esperaba la orden #{orden.numero_pedido} pero se escaneó "{codigo_escaneado}".', 'error')

    return redirect(url_for('detalle_despacho', orden_id=orden_id))



# 5. PUNTO DE ENTRADA
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)