# limpiar_db.py

# 1. Importamos todo lo necesario, incluyendo los nuevos modelos
from app import app, db, Orden, LotePicking, IncidenciaHistorial, ItemOrden, HojaDeRuta, Bulto, Transaccion, GastoViaje, Destino
# ¡Importante! No importamos el modelo 'User' para no borrar los usuarios.

def limpiar_datos_operativos():
    """
    Borra todos los datos de las tablas operativas pero deja a los usuarios y destinos intactos.
    """
    try:
        # El orden de borrado es crucial por las relaciones (foreign keys).
        # Borramos desde los "hijos más lejanos" hacia los "padres".

        print("Iniciando limpieza de la base de datos...")

        # 1. Borrar Gastos y Transacciones (dependen de HojaDeRuta y Orden)
        num_gastos = db.session.query(GastoViaje).delete()
        num_transacciones = db.session.query(Transaccion).delete()
        
        # 2. Borrar Historial de Incidencias (depende de ItemOrden)
        num_incidencias = db.session.query(IncidenciaHistorial).delete()
        
        # 3. Borrar Bultos y Items (dependen de Orden)
        num_bultos = db.session.query(Bulto).delete()
        num_items = db.session.query(ItemOrden).delete()

        # 4. Ahora podemos borrar las Órdenes (dependen de Lote y HojaDeRuta)
        #    (No borramos Destinos, ya que son datos maestros como los usuarios)
        num_ordenes = db.session.query(Orden).delete()

        # 5. Finalmente, borramos los Lotes y Hojas de Ruta
        num_lotes = db.session.query(LotePicking).delete()
        num_rutas = db.session.query(HojaDeRuta).delete()
        
        # 6. Opcional: Si también quieres limpiar la tabla de Destinos (descomenta la línea)
        num_destinos = db.session.query(Destino).delete()


        # Guardamos los cambios en la base de datos
        db.session.commit()
        
        print("\n--- ¡Limpieza completada! ---")
        print(f"Borrados {num_rutas} hojas de ruta.")
        print(f"Borrados {num_lotes} lotes.")
        print(f"Borrados {num_ordenes} órdenes.")
        print(f"Borrados {num_bultos} bultos.")
        print(f"Borrados {num_items} ítems.")
        print(f"Borrados {num_incidencias} registros de incidencia.")
        print(f"Borrados {num_transacciones} transacciones (pagos).")
        print(f"Borrados {num_gastos} gastos de viaje.")
        if 'num_destinos' in locals():
            print(f"Borrados {num_destinos} destinos.")
        print("\nLos usuarios NO han sido modificados.")

    except Exception as e:
        # Si algo sale mal, deshacemos los cambios para mantener la BD consistente
        db.session.rollback()
        print(f"\n!!! Ocurrió un error durante la limpieza: {e}")
        print("!!! Se han revertido todos los cambios.")

if __name__ == '__main__':
    # Pedimos confirmación para evitar accidentes
    print("Este script borrará TODOS los datos operativos (rutas, lotes, órdenes, etc.).")
    print("Los datos de USUARIOS NO serán borrados.")
    confirmacion = input("¿Está seguro de que desea continuar? (escriba 'si' para confirmar): ")
    
    if confirmacion.lower() == 'si':
        # Usamos app_context para que el script pueda interactuar con la app Flask
        with app.app_context():
            limpiar_datos_operativos()
    else:
        print("Limpieza cancelada.")