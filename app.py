# 1. IMPORTACIONES
from sqlalchemy.orm import joinedload
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
import qrcode
import io
from flask import send_file
from flask_migrate import Migrate # Importar Migrate
from flask_weasyprint import HTML, render_pdf


# 2. CONFIGURACIÓN DE LA APP
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///picking_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'una-clave-secreta-muy-dificil-de-adivinar')
app.config['API_SECRET_KEY'] = os.environ.get('API_SECRET_KEY', 'MI_CLAVE_SUPER_SECRETA_12345')

db = SQLAlchemy(app)
migrate = Migrate(app, db) # Inicializar Migrate

# --- CONFIGURACIÓN DE FLASK-LOGIN ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."
login_manager.login_message_category = "error"

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
    if not utc_datetime: return ""
    local_tz = pytz.timezone('America/Costa_Rica')
    local_dt = utc_datetime.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_dt.strftime('%d-%m-%Y %H:%M:%S')



# 3. MODELOS DE LA BASE DE DATOS
class LotePicking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    estado = db.Column(db.String(20), nullable=False, default='ACTIVO')
    ordenes = db.relationship('Orden', backref='lote', lazy=True)
    operario_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    operario = db.relationship('User', backref='lotes_asignados')

class Orden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    numero_pedido = db.Column(db.String(50), unique=True, nullable=False)
    cliente_nombre = db.Column(db.String(200), nullable=False)
    cliente_direccion = db.Column(db.String(300), nullable=True)
    estado = db.Column(db.String(30), nullable=False, default='PENDIENTE')
    fecha_creacion = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    lote_id = db.Column(db.Integer, db.ForeignKey('lote_picking.id'), nullable=True)
    items = db.relationship('ItemOrden', backref='orden', lazy=True, cascade="all, delete-orphan")
    fecha_inicio_picking = db.Column(db.DateTime, nullable=True)
    fecha_fin_picking = db.Column(db.DateTime, nullable=True)
    fecha_fin_packing = db.Column(db.DateTime, nullable=True)
    fecha_despacho = db.Column(db.DateTime, nullable=True)
    packer_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    packer = db.relationship('User', foreign_keys=[packer_id])
    devolucion_confirmada = db.Column(db.Boolean, default=False, nullable=False)
    bultos = db.relationship('Bulto', backref='orden', cascade="all, delete-orphan")
    hoja_de_ruta_id = db.Column(db.Integer, db.ForeignKey('hoja_de_ruta.id'), nullable=True)
    def __repr__(self): return f'<Orden {self.numero_pedido}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='operario')
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def __repr__(self): return f'<User {self.username}>'

class ItemOrden(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id'), nullable=False)
    codigo_articulo = db.Column(db.String(100), nullable=False)
    descripcion_articulo = db.Column(db.String(300), nullable=False)
    cantidad_solicitada = db.Column(db.Integer, nullable=False)
    cantidad_recogida = db.Column(db.Integer, nullable=False, default=0)
    cantidad_empacada = db.Column(db.Integer, nullable=False, default=0)
    tiene_incidencia = db.Column(db.Boolean, default=False, nullable=False)
    tipo_incidencia = db.Column(db.String(50), nullable=True)
    nota_incidencia = db.Column(db.Text, nullable=True)
    def __repr__(self): return f'<Item {self.codigo_articulo} de Orden {self.orden_id}>'

class IncidenciaHistorial(db.Model):
    __tablename__ = 'incidencia_historial'
    id = db.Column(db.Integer, primary_key=True)
    fecha_reporte = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    tipo_incidencia = db.Column(db.String(50), nullable=False)
    nota_incidencia = db.Column(db.Text, nullable=True)
    cantidad_solicitada_original = db.Column(db.Integer, nullable=False)
    cantidad_recogida_reportada = db.Column(db.Integer, nullable=False)
    item_orden_id = db.Column(db.Integer, db.ForeignKey('item_orden.id', ondelete='CASCADE'), nullable=False)
    reportado_por_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    item_orden = db.relationship('ItemOrden', backref=db.backref('historial_incidencias', cascade="all, delete-orphan"))
    reportado_por = db.relationship('User', foreign_keys=[reportado_por_id])
    estado_resolucion = db.Column(db.String(20), nullable=False, default='PENDIENTE')
    fecha_resolucion = db.Column(db.DateTime, nullable=True)
    resuelta_por_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    nota_resolucion = db.Column(db.Text, nullable=True)
    resuelta_por = db.relationship('User', foreign_keys=[resuelta_por_id])
    def __repr__(self): return f'<Incidencia #{self.id} para ItemOrden {self.item_orden_id}>'

class Bulto(db.Model):
    __tablename__ = 'bulto'
    id = db.Column(db.Integer, primary_key=True)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id'), nullable=False)
    tipo = db.Column(db.String(20), nullable=False)
    identificador_unico = db.Column(db.String(100), unique=True, nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def __repr__(self): return f'<Bulto {self.identificador_unico} para Orden {self.orden_id}>'

class Destino(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), unique=True, nullable=False)
    def __repr__(self): return f'<Destino {self.nombre}>'

class HojaDeRuta(db.Model):
    __tablename__ = 'hoja_de_ruta'
    id = db.Column(db.Integer, primary_key=True)
    fecha_creacion = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    estado = db.Column(db.String(20), nullable=False, default='EN_PREPARACION')
    gastos_asignados = db.Column(db.Float, nullable=False, default=0.0)
    ordenes = db.relationship('Orden', backref='hoja_de_ruta', lazy='dynamic')
    transacciones = db.relationship('Transaccion', backref='hoja_de_ruta', lazy='dynamic', cascade="all, delete-orphan")
    gastos_viaje = db.relationship('GastoViaje', backref='hoja_de_ruta', lazy='dynamic', cascade="all, delete-orphan")
    
    ### --- INICIO: CAMBIOS PARA RUTAS EXTERNAS --- ###
    
    # Campo para distinguir el tipo de entrega
    tipo_entrega = db.Column(db.String(20), nullable=False, default='INTERNA') # Valores: 'INTERNA', 'EXTERNA'
    
    # Para entregas INTERNAS (conductor de la empresa)
    conductor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Ahora es opcional
    conductor = db.relationship('User', backref='hojas_de_ruta')

    # Para entregas EXTERNAS (transportista externo)
    nombre_transportista = db.Column(db.String(100), nullable=True) # Ej: "Guatex", "Cargo Expreso"
    nombre_receptor = db.Column(db.String(100), nullable=True)     # Nombre de la persona que recibe
    id_receptor = db.Column(db.String(50), nullable=True)          # DPI, Cédula, etc.
    
    ### --- FIN: CAMBIOS PARA RUTAS EXTERNAS --- ###

    def __repr__(self): return f'<HojaDeRuta #{self.id} de tipo {self.tipo_entrega}>'

class Transaccion(db.Model):
    __tablename__ = 'transaccion'
    id = db.Column(db.Integer, primary_key=True)
    hoja_de_ruta_id = db.Column(db.Integer, db.ForeignKey('hoja_de_ruta.id'), nullable=False)
    orden_id = db.Column(db.Integer, db.ForeignKey('orden.id'), nullable=False)
    orden = db.relationship('Orden')
    monto_recibido = db.Column(db.Float, nullable=False)
    nota = db.Column(db.Text, nullable=True)
    fecha_registro = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def __repr__(self): return f'<Transaccion de {self.monto_recibido} para Orden #{self.orden_id}>'

class GastoViaje(db.Model):
    __tablename__ = 'gasto_viaje'
    id = db.Column(db.Integer, primary_key=True)
    hoja_de_ruta_id = db.Column(db.Integer, db.ForeignKey('hoja_de_ruta.id'), nullable=False)
    monto_gastado = db.Column(db.Float, nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def __repr__(self): return f'<Gasto de {self.monto_gastado} en HojaDeRuta #{self.hoja_de_ruta_id}>'


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
    lista_consolidada = defaultdict(lambda: {'descripcion': '', 'solicitado': 0, 'recogido': 0, 'items_individuales': []})
    
    for orden in lote.ordenes:
        for item in orden.items:
            consolidado = lista_consolidada[item.codigo_articulo]
            consolidado['descripcion'] = item.descripcion_articulo
            consolidado['solicitado'] += item.cantidad_solicitada
            consolidado['recogido'] += item.cantidad_recogida
            consolidado['items_individuales'].append(item)
            
    lista_final = sorted(lista_consolidada.items(), key=lambda x: x[0])
    picking_completo = all(item['recogido'] >= item['solicitado'] for _, item in lista_consolidada.items()) if lista_consolidada else False

    return render_template('detalle_lote.html', lote=lote, lista_consolidada=lista_final, picking_completo=picking_completo )

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
    # Ya no usamos la sesión. Ahora es la BD.
    orden = Orden.query.get_or_404(orden_id)
    data = request.get_json()
    codigo_escaneado = data.get('codigo_articulo', '').strip()

    item_encontrado = next((item for item in orden.items if item.codigo_articulo == codigo_escaneado), None)

    if not item_encontrado:
        return jsonify({'success': False, 'message': f'El artículo {codigo_escaneado} no pertenece a esta orden.'}), 404

    # Verificamos contra la base de datos
    if item_encontrado.cantidad_empacada < item_encontrado.cantidad_solicitada:
        item_encontrado.cantidad_empacada += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Artículo verificado.',
            'codigo_articulo': item_encontrado.codigo_articulo,
            'escaneado': item_encontrado.cantidad_empacada, # Devolvemos el nuevo total desde la BD
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


@app.route('/packing/<int:orden_id>', methods=['GET']) # Ya no necesitamos POST aquí
@login_required
def detalle_packing(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    if orden.estado != 'EMPACADO':
        flash('Esta orden no está lista para packing.', 'error')
        return redirect(url_for('dashboard_packing'))

    # Ya no necesitamos manejar la sesión. La vista leerá el estado
    # directamente desde la base de datos.
    # Al entrar a la pantalla de packing, podríamos querer resetear el conteo,
    # por si alguien la dejó a medias y quiere empezar de nuevo.
    if request.args.get('reset') == 'true':
        for item in orden.items:
            # Solo reseteamos los items físicos, no los de servicio
            if item.codigo_articulo not in CODIGOS_DE_SERVICIO:
                item.cantidad_empacada = 0
        db.session.commit()
        flash('Se ha reiniciado el conteo de packing para esta orden.', 'info')
        return redirect(url_for('detalle_packing', orden_id=orden.id))

    return render_template('detalle_packing.html', orden=orden)


# En app.py, esta DEBE ser tu nueva función finalizar_packing

@app.route('/packing/<int:orden_id>/finalizar', methods=['POST'])
@login_required
def finalizar_packing(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    if orden.estado != 'EMPACADO':
        flash('Esta orden no está en el estado correcto para finalizar el packing.', 'error')
        return redirect(url_for('dashboard_packing'))

    try:
        num_cajas = int(request.form.get('cantidad_cajas', 0))
        num_bolsas = int(request.form.get('cantidad_bolsas', 0))
        num_paquetes = int(request.form.get('cantidad_paquetes', 0))
    except (ValueError, TypeError):
        flash('Las cantidades deben ser números válidos.', 'error')
        return redirect(url_for('detalle_packing', orden_id=orden_id))

    if num_cajas + num_bolsas + num_paquetes == 0:
        flash('Debe especificar al menos un bulto (caja, bolsa o paquete).', 'error')
        return redirect(url_for('detalle_packing', orden_id=orden_id))

    bulto_counter = 1
    for _ in range(num_cajas):
        nuevo_bulto = Bulto(orden_id=orden.id, tipo='CAJA', identificador_unico=f'{orden.numero_pedido}-{bulto_counter}')
        db.session.add(nuevo_bulto)
        bulto_counter += 1
    
    for _ in range(num_bolsas):
        nuevo_bulto = Bulto(orden_id=orden.id, tipo='BOLSA', identificador_unico=f'{orden.numero_pedido}-{bulto_counter}')
        db.session.add(nuevo_bulto)
        bulto_counter += 1

    for _ in range(num_paquetes):
        nuevo_bulto = Bulto(orden_id=orden.id, tipo='PAQUETE', identificador_unico=f'{orden.numero_pedido}-{bulto_counter}')
        db.session.add(nuevo_bulto)
        bulto_counter += 1
        
    orden.estado = 'LISTO_PARA_DESPACHO'
    orden.fecha_fin_packing = datetime.datetime.utcnow()
    orden.packer_id = current_user.id
    
    db.session.commit()
    session.pop(f'packing_{orden_id}', None)
    flash(f'Orden #{orden.numero_pedido} finalizada. Se generaron {bulto_counter - 1} etiquetas.', 'success')
    
    return redirect(url_for('imprimir_etiquetas', orden_id=orden.id))

# === INICIO: NUEVAS RUTAS PARA IMPRESIÓN Y QR (PASO 4) ===
@app.route('/orden/<int:orden_id>/imprimir-etiquetas')
@login_required
def imprimir_etiquetas(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    # Gracias a la relación 'backref', podemos acceder a orden.bultos directamente.
    # No necesitamos hacer una consulta extra.
    return render_template('imprimir_etiquetas.html', orden=orden)

@app.route('/bulto/<identificador_unico>/qr_code')
@login_required
def qr_code_generator(identificador_unico):
    try:
        # Generamos la imagen del código QR en memoria RAM
        img = qrcode.make(identificador_unico)
        
        # Creamos un buffer de bytes para guardar la imagen
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0) # Rebobinamos el buffer al principio
        
        # Enviamos el buffer como un archivo de imagen PNG
        return send_file(buf, mimetype='image/png')
    except Exception as e:
        print(f"Error generando QR para '{identificador_unico}': {e}")
        return "Error", 500
# === FIN: NUEVAS RUTAS ===
    

    
@app.route('/despacho')
@login_required
def dashboard_despacho():
    """Muestra el dashboard con las órdenes listas para ser despachadas."""
    ordenes_para_despacho = Orden.query.filter_by(estado='LISTO_PARA_DESPACHO').order_by(Orden.fecha_creacion.asc()).all()
    return render_template('dashboard_despacho.html', ordenes=ordenes_para_despacho)

@app.route('/despacho/<int:orden_id>')
@login_required
def detalle_despacho(orden_id):
    """
    Muestra la página de checklist para la verificación de bultos por escaneo.
    """
    orden = Orden.query.get_or_404(orden_id)
    if orden.estado != 'LISTO_PARA_DESPACHO':
        flash(f'La orden #{orden.numero_pedido} no está lista para despacho.', 'warning')
        return redirect(url_for('dashboard_despacho'))

    # Limpiamos la sesión de verificación anterior al cargar la página
    session_key = f'despacho_bultos_verificados_{orden_id}'
    if session_key in session:
        session.pop(session_key)

    return render_template('detalle_despacho.html', orden=orden)

@app.route('/api/despacho/<int:orden_id>/verificar-bulto', methods=['POST'])
@login_required
def api_verificar_bulto_despacho(orden_id):
    """
    API para verificar un bulto escaneado contra la lista de la orden.
    """
    data = request.get_json()
    identificador_escaneado = data.get('identificador_unico', '').strip()

    orden = Orden.query.get_or_404(orden_id)
    bulto_encontrado = Bulto.query.filter_by(identificador_unico=identificador_escaneado).first()

    if not bulto_encontrado or bulto_encontrado.orden_id != orden.id:
        return jsonify({'success': False, 'message': f'¡Bulto incorrecto! El bulto {identificador_escaneado} no pertenece a esta orden.'}), 422

    # Guardamos los bultos verificados en la sesión del usuario
    session_key = f'despacho_bultos_verificados_{orden_id}'
    bultos_verificados = session.get(session_key, [])
    if identificador_escaneado not in bultos_verificados:
        bultos_verificados.append(identificador_escaneado)
        session[session_key] = bultos_verificados

    todos_verificados = len(bultos_verificados) == len(orden.bultos)

    return jsonify({
        'success': True,
        'message': f'Bulto {identificador_escaneado} verificado.',
        'identificador_verificado': identificador_escaneado,
        'todos_verificados': todos_verificados
    })

@app.route('/despacho/<int:orden_id>/finalizar', methods=['POST'])
@login_required
def finalizar_despacho(orden_id):
    """
    Procesa el formulario final de despacho.
    """
    orden = Orden.query.get_or_404(orden_id)
    session_key = f'despacho_bultos_verificados_{orden_id}'
    
    # Doble verificación de seguridad
    if len(session.get(session_key, [])) != len(orden.bultos):
        flash('Error de seguridad: No todos los bultos han sido verificados.', 'error')
        return redirect(url_for('detalle_despacho', orden_id=orden_id))

    orden.transportista = request.form.get('transportista')
    orden.numero_seguimiento = request.form.get('numero_seguimiento')
    orden.estado = 'DESPACHADO'
    orden.fecha_despacho = datetime.datetime.utcnow()
    db.session.commit()

    session.pop(session_key, None)
    flash(f'¡Orden #{orden.numero_pedido} despachada con éxito!', 'success')
    return redirect(url_for('dashboard_despacho'))

# --- RUTA PARA REPORTES Y BÚSQUEDA ---
# En app.py, reemplaza esta función completa

@app.route('/reportes', methods=['GET', 'POST'])
@login_required
@admin_required
def reportes_y_busqueda():
    orden_encontrada = None
    historial_busqueda = session.get('historial_busqueda', [])

    if request.method == 'POST':
        # ... (tu lógica de búsqueda POST no cambia) ...
        numero_pedido_buscado = request.form.get('numero_pedido', '').strip()
        if numero_pedido_buscado:
            orden_encontrada = Orden.query.filter(Orden.numero_pedido.ilike(f"%{numero_pedido_buscado}%")).first()
            if not orden_encontrada:
                flash(f'No se encontró ninguna orden con el número "{numero_pedido_buscado}".', 'error')
            else:
                if orden_encontrada.numero_pedido in historial_busqueda:
                    historial_busqueda.remove(orden_encontrada.numero_pedido)
                historial_busqueda.insert(0, orden_encontrada.numero_pedido)
                session['historial_busqueda'] = historial_busqueda[:5]

    # --- CÁLCULO DE ESTADÍSTICAS OPTIMIZADO EN UNA SOLA CONSULTA ---
    stats = {
        'tiempo_picking_avg': 'N/A',
        'tiempo_packing_avg': 'N/A',
        'tiempo_ciclo_completo_avg': 'N/A',
        'ordenes_hoy': 0
    }

    try:
        # Definir expresiones de diferencia de tiempo compatibles con la BD
        dialect_name = db.engine.dialect.name
        if dialect_name == 'postgresql':
            diff_picking = func.extract('epoch', Orden.fecha_fin_picking) - func.extract('epoch', Orden.fecha_inicio_picking)
            diff_packing = func.extract('epoch', Orden.fecha_fin_packing) - func.extract('epoch', Orden.fecha_fin_picking)
            diff_ciclo_completo = func.extract('epoch', Orden.fecha_despacho) - func.extract('epoch', Orden.fecha_creacion)
        else: # SQLite
            diff_picking = func.strftime('%s', Orden.fecha_fin_picking) - func.strftime('%s', Orden.fecha_inicio_picking)
            diff_packing = func.strftime('%s', Orden.fecha_fin_packing) - func.strftime('%s', Orden.fecha_fin_picking)
            diff_ciclo_completo = func.strftime('%s', Orden.fecha_despacho) - func.strftime('%s', Orden.fecha_creacion)

        # Definir el rango para "órdenes de hoy"
        hoy_inicio = datetime.datetime.combine(datetime.date.today(), datetime.time.min)
        hoy_fin = datetime.datetime.combine(datetime.date.today(), datetime.time.max)

        # Ejecutamos UNA SOLA consulta que calcula todo
        resultado_stats = db.session.query(
            func.avg(diff_picking),
            func.avg(diff_packing),
            func.avg(diff_ciclo_completo),
            func.count(Orden.id).filter(Orden.fecha_creacion.between(hoy_inicio, hoy_fin))
        ).one()

        # Desempaquetamos los resultados y los formateamos
        avg_pick_s, avg_pack_s, avg_ciclo_s, ordenes_hoy = resultado_stats
        
        if avg_pick_s is not None:
            stats['tiempo_picking_avg'] = str(timedelta(seconds=int(avg_pick_s)))
        if avg_pack_s is not None:
            stats['tiempo_packing_avg'] = str(timedelta(seconds=int(avg_pack_s)))
        if avg_ciclo_s is not None:
            stats['tiempo_ciclo_completo_avg'] = str(timedelta(seconds=int(avg_ciclo_s)))
        
        stats['ordenes_hoy'] = ordenes_hoy or 0

    except Exception as e:
        print(f"Error calculando estadísticas del dashboard: {e}")
        flash('Ocurrió un error al calcular las estadísticas.', 'error')

    return render_template('reportes.html', stats=stats, orden=orden_encontrada, historial=historial_busqueda)

@app.route('/rutas', methods=['GET', 'POST'])
@login_required
@admin_required
def gestionar_rutas():
    if request.method == 'POST':
        conductor_id = request.form.get('conductor_id')
        gastos_str = request.form.get('gastos_asignados', '0').replace(',', '.')

        # --- Validación ---
        if not conductor_id:
            flash('Debe seleccionar un conductor.', 'error')
        else:
            try:
                gastos = float(gastos_str)
                if gastos < 0:
                    flash('Los gastos asignados no pueden ser negativos.', 'error')
                else:
                    # --- Creación de la Hoja de Ruta ---
                    nueva_ruta = HojaDeRuta(
                        conductor_id=int(conductor_id),
                        gastos_asignados=gastos
                    )
                    db.session.add(nueva_ruta)
                    db.session.commit()
                    flash(f'Hoja de Ruta #{nueva_ruta.id} creada con éxito.', 'success')
                    # Redirigimos para "limpiar" el formulario POST
                    return redirect(url_for('gestionar_rutas'))
            except ValueError:
                flash('El valor de los gastos asignados no es un número válido.', 'error')

    # --- Lógica para GET (cargar la página) ---
    # Usamos joinedload para cargar el conductor relacionado y evitar consultas extra en el bucle
    rutas = HojaDeRuta.query.options(joinedload(HojaDeRuta.conductor)).order_by(HojaDeRuta.fecha_creacion.desc()).all()
    
    # Obtenemos la lista de usuarios que pueden ser asignados como conductores
    conductores = User.query.filter_by(role='conductor').order_by(User.username).all()
    
    return render_template('gestionar_rutas.html', rutas=rutas, conductores=conductores)



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



@app.route('/api/lote/<int:lote_id>/codigo/<codigo_articulo>/completar', methods=['POST'])
@login_required
@admin_required
def api_completar_codigo_picking(lote_id, codigo_articulo):
    """
    Permite a un admin marcar todos los items con un código específico dentro 
    de un lote como completamente recogidos.
    """
    lote = LotePicking.query.get_or_404(lote_id)
    
    total_solicitado_en_lote = 0
    total_recogido_previo = 0

    # Primero, calculamos los totales para devolver la información correcta
    for orden in lote.ordenes:
        for item in orden.items:
            if item.codigo_articulo == codigo_articulo:
                total_solicitado_en_lote += item.cantidad_solicitada
                total_recogido_previo += item.cantidad_recogida # Para saber si ya estaba parcialmente recogido

    # Segundo, actualizamos la base de datos
    for orden in lote.ordenes:
        for item in orden.items:
            if item.codigo_articulo == codigo_articulo:
                item.cantidad_recogida = item.cantidad_solicitada

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error al completar item manualmente: {e}")
        return jsonify({'success': False, 'message': 'Error al guardar en la base de datos.'}), 500

    return jsonify({
        'success': True,
        'message': f'Ítem {codigo_articulo} completado manualmente.',
        'codigo_articulo': codigo_articulo,
        'recogido': total_solicitado_en_lote, # Ahora lo recogido es igual a lo solicitado
        'solicitado': total_solicitado_en_lote
    })
    
@app.route('/api/packing/item/<int:item_id>/completar', methods=['POST'])
@login_required
@admin_required
def api_completar_item_packing(item_id):
    # Esta función ahora será mucho más poderosa porque afectará a todos
    item = ItemOrden.query.get_or_404(item_id)
    
    # Actualizamos el conteo directamente en la base de datos
    item.cantidad_empacada = item.cantidad_solicitada
    db.session.commit()
    
    print(f"Admin completó el ítem {item.codigo_articulo} para la orden #{item.orden_id}")

    return jsonify({
        'success': True,
        'message': f'Ítem {item.codigo_articulo} completado por admin.',
        'codigo_articulo': item.codigo_articulo,
        'escaneado': item.cantidad_empacada,
        'solicitado': item.cantidad_solicitada
    })  
    
@app.route('/orden/<int:orden_id>/etiquetas.pdf')
@login_required
def generar_pdf_etiquetas(orden_id):
    """
    Renderiza un template HTML y lo convierte en un PDF de etiquetas.
    """
    orden = Orden.query.get_or_404(orden_id)
    
    # Renderizamos el template HTML específico para el PDF
    html_renderizado = render_template('etiqueta_pdf.html', orden=orden)
    
    # Creamos un objeto HTML a partir del string renderizado
    html_obj = HTML(string=html_renderizado, base_url=request.base_url)
    
    # Devolvemos el PDF renderizado directamente al navegador
    return render_pdf(html_obj)  

@app.route('/ruta/<int:ruta_id>')
@login_required
@admin_required
def detalle_ruta(ruta_id):
    # Buscamos la hoja de ruta específica o mostramos un error 404
    ruta = HojaDeRuta.query.get_or_404(ruta_id)

    # La consulta para las órdenes disponibles es la clave aquí:
    # Deben estar LISTAS_PARA_DESPACHO y no tener ninguna hoja_de_ruta_id asignada.
    ordenes_disponibles = Orden.query.filter(
        Orden.estado == 'LISTO_PARA_DESPACHO',
        Orden.hoja_de_ruta_id.is_(None)
    ).order_by(Orden.fecha_creacion.asc()).all()

    # Las órdenes ya asignadas las obtenemos directamente de la relación
    ordenes_asignadas = ruta.ordenes.order_by(Orden.numero_pedido).all()

    return render_template(
        'detalle_ruta.html', 
        ruta=ruta, 
        ordenes_asignadas=ordenes_asignadas,
        ordenes_disponibles=ordenes_disponibles
    )
    
@app.route('/ruta/<int:ruta_id>/agregar-ordenes', methods=['POST'])
@login_required
@admin_required
def agregar_ordenes_a_ruta(ruta_id):
    ruta = HojaDeRuta.query.get_or_404(ruta_id)
    
    # Obtenemos la lista de IDs de las órdenes seleccionadas en el formulario
    orden_ids_a_agregar = request.form.getlist('orden_id')

    if not orden_ids_a_agregar:
        flash('No se seleccionó ninguna orden para agregar.', 'warning')
        return redirect(url_for('detalle_ruta', ruta_id=ruta_id))

    for orden_id in orden_ids_a_agregar:
        orden = Orden.query.get(orden_id)
        # Doble chequeo de seguridad
        if orden and orden.estado == 'LISTO_PARA_DESPACHO' and orden.hoja_de_ruta_id is None:
            orden.hoja_de_ruta_id = ruta.id
    
    db.session.commit()
    flash(f'{len(orden_ids_a_agregar)} órdenes han sido añadidas a la ruta #{ruta.id}.', 'success')
    return redirect(url_for('detalle_ruta', ruta_id=ruta_id))


@app.route('/ruta/quitar-orden/<int:orden_id>', methods=['POST'])
@login_required
@admin_required
def quitar_orden_de_ruta(orden_id):
    orden = Orden.query.get_or_404(orden_id)
    ruta_id_actual = orden.hoja_de_ruta_id

    if ruta_id_actual is None:
        flash('Esta orden no está asignada a ninguna ruta.', 'error')
        return redirect(url_for('gestionar_rutas')) # Redirigir a la vista general si hay un problema

    # Simplemente "liberamos" la orden
    orden.hoja_de_ruta_id = None
    db.session.commit()
    
    flash(f'La orden #{orden.numero_pedido} ha sido quitada de la ruta.', 'success')
    return redirect(url_for('detalle_ruta', ruta_id=ruta_id_actual))



# 5. PUNTO DE ENTRADA
if __name__ == '__main__':
    
    app.run(debug=True, port=5000)