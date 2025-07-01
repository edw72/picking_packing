# limpiar_db.py

from app import app, db, Orden, LotePicking, IncidenciaHistorial, ItemOrden
# ¡Importante! No importamos el modelo 'User' para no borrar los usuarios.

def limpiar_datos_operativos():
    """
    Borra todos los datos de las tablas operativas pero deja a los usuarios intactos.
    """
    try:
        # El orden de borrado es importante por las relaciones (foreign keys).
        # Borramos primero los "hijos" y luego los "padres".

        # 1. Borrar Historial de Incidencias
        num_incidencias = db.session.query(IncidenciaHistorial).delete()
        
        # 2. Borrar Items de Órdenes
        num_items = db.session.query(ItemOrden).delete()
        
        # 3. Borrar Órdenes
        num_ordenes = db.session.query(Orden).delete()

        # 4. Borrar Lotes
        num_lotes = db.session.query(LotePicking).delete()

        # Guardamos los cambios en la base de datos
        db.session.commit()
        
        print("--- ¡Limpieza completada! ---")
        print(f"Borrados {num_lotes} lotes.")
        print(f"Borrados {num_ordenes} órdenes.")
        print(f"Borrados {num_items} ítems.")
        print(f"Borrados {num_incidencias} registros de incidencia.")
        print("\nLos usuarios no han sido modificados.")

    except Exception as e:
        # Si algo sale mal, deshacemos los cambios
        db.session.rollback()
        print(f"!!! Ocurrió un error durante la limpieza: {e}")

if __name__ == '__main__':
    # Pedimos confirmación para evitar accidentes
    confirmacion = input("¿Estás seguro de que quieres borrar TODOS los lotes, órdenes e incidencias? (escriba 'si' para confirmar): ")
    if confirmacion.lower() == 'si':
        with app.app_context():
            limpiar_datos_operativos()
    else:
        print("Limpieza cancelada.")