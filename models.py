from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Instancia de SQLAlchemy para manejar la base de datos
db = SQLAlchemy()

# Modelo para las tareas
class Task(db.Model):
    __tablename__ = 'tasks'  # Nombre explícito de la tabla en la base de datos

    id = db.Column(db.Integer, primary_key=True)  # Identificador único de la tarea
    content = db.Column(db.String(200), nullable=False)  # Texto de la tarea (no puede estar vacío)
    completed = db.Column(db.Boolean, default=False)  # Indica si la tarea está completada (por defecto False)

    def __repr__(self):
        # Representación en texto para facilitar la depuración
        return f'<Task {self.id} - {self.content} - Completed: {self.completed}>'

# Modelo para los usuarios, hereda de UserMixin para funcionalidades de login
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Identificador único del usuario
    username = db.Column(db.String(80), unique=True, nullable=False)  # Nombre de usuario único y obligatorio
    password_hash = db.Column(db.String(128), nullable=False)  # Hash de la contraseña (nunca almacenar texto plano)

    # Relación uno a muchos: un usuario puede tener muchas tareas
    tasks = db.relationship('Task', backref='user', lazy=True)

    def set_password(self, password):
        # Genera y almacena el hash seguro de la contraseña
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Comprueba que la contraseña introducida coincide con el hash almacenado
        return check_password_hash(self.password_hash, password)
