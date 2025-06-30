# create_admin.py

from app import app, db, User

def create_admin_user():
    # Usamos app_context para poder interactuar con la base de datos
    with app.app_context():
        # Comprueba si el usuario ya existe
        if User.query.filter_by(username='admin').first():
            print("El usuario 'admin' ya existe.")
            return

        # Crea un nuevo usuario
        admin_user = User(username='admin', role='admin')
        # Pide una contraseña segura por terminal
        password = input("Ingrese la contraseña para el usuario 'admin': ")
        admin_user.set_password(password)
        
        db.session.add(admin_user)
        db.session.commit()
        print("¡Usuario 'admin' creado con éxito!")

if __name__ == '__main__':
    create_admin_user()