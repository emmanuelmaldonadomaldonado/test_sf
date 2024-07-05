from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import secrets
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import relationship
from sqlalchemy import func, text, or_, Column, String, Integer, Float, Boolean, DateTime, ForeignKey

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)

class users(UserMixin, db.Model):
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    email_verified = Column(Boolean, default=False)  # Nuevo campo para verificar el correo electrónico
    date_created = Column(DateTime, default=datetime.utcnow) 
    confirmation_token = Column(String(100), unique=True, nullable=True)  # Campo para almacenar el token de verificación

    def __repr__(self):
        return '<users %r>' % self.id

def generate_confirmation_token(self):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(self.email)

def confirm_email(self, token):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(token, max_age=3600)  # El token es válido por 1 hora (3600 segundos)
    except:
        return False
    if email == self.email:
        self.email_verified = True
        db.session.commit()
        return True
    return False

class products(db.Model):
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    quantity = Column(Integer, nullable=False)
    description = Column(String(256), nullable=True)
    total_price = Column(Float, nullable=True)
    date_created = Column(DateTime, default=datetime.utcnow)
    date_updated = Column(DateTime, nullable=False, server_default=text('CURRENT_TIMESTAMP'), onupdate=datetime.utcnow)
    deleted = Column(Boolean, default=False)
    alert_quantity = Column(Integer, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)  # Añadido campo user_id
    user = relationship('users', backref='products')  # Relación con el modelo users

    def __repr__(self):
        return '<Product %r>' % self.id

class productHistory(db.Model):
    __tablename__ = 'product_history'
    history_id = Column(Integer, primary_key=True)
    product_id = Column(Integer, ForeignKey('products.id'), nullable=False)
    product_name = Column(String(255), nullable=False)
    quantity = Column(Integer, nullable=False)
    restocking_price = Column(Float, nullable=True)  # Nuevo campo para el precio de reabastecimiento
    date = Column(DateTime, nullable=False, default=datetime.utcnow)  # Campo de fecha para el historial
    product = relationship('products', backref='history')

    def __repr__(self):
        return '<productHistory %r>' % self.history_id


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

def send_verification_email(user_email):
    token = secrets.token_urlsafe(20)  # Genera un token único
    verification_link = url_for('confirm_email', token=token, _external=True)
    message = Mail(
        from_email='maldonadomaldonadoemmanuel227@gmail.com',
        to_emails=user_email,
        subject='Verificación de correo electrónico',
        html_content=f'Por favor, haz clic en el siguiente enlace para verificar tu correo electrónico: <a href="{verification_link}">Verificar correo electrónico</a>'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

@app.route('/', methods=['GET'])
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect('/actions')
            else:
                flash('Incorrect password. Please try again.', 'error')
                return redirect('/login')
        else:
            flash('User does not exist. Please sign up.', 'error')
            return redirect('/login')
    else:
        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Verificar si la contraseña cumple con las restricciones
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash('La contraseña debe tener al menos 8 caracteres, una mayúscula, un número y un símbolo especial.', 'error')
            return redirect('/signup')

        if password != confirm_password:
            flash('Las contraseñas no coinciden. Por favor, inténtalo de nuevo.', 'error')
            return redirect('/signup')

        hashed_password = generate_password_hash(password)
        new_user = users(email=email, password=hashed_password)

        try:
            send_verification_email(new_user.email)
            
            db.session.add(new_user)
            db.session.commit()

            flash('Cuenta creada exitosamente. Por favor, verifica tu correo electrónico.', 'success')
            return redirect('/login')
        except:
            flash('Error al crear la cuenta. Por favor, inténtalo de nuevo.', 'error')
            return redirect('/signup')
    else:
        return render_template('signup.html')

# Ruta para la confirmación del correo electrónico
@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    user = users.query.filter_by(confirmation_token=token).first()
    if user is None:
        return render_template('confirm_email.html', email_confirmed=False)
    user.email_verified = True
    db.session.commit()
    return render_template('confirm_email.html', email_confirmed=True)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not check_password_hash(current_user.password, current_password):
        flash('La contraseña actual es incorrecta. Por favor, inténtalo de nuevo.', 'error')
        return redirect('/settings')

    if new_password != confirm_password:
        flash('Las contraseñas nuevas no coinciden. Por favor, inténtalo de nuevo.', 'error')
        return redirect('/settings')

    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', new_password):
        flash('La nueva contraseña debe tener al menos 8 caracteres, una mayúscula, un número y un símbolo especial.', 'error')
        return redirect('/settings')

    current_user.password = generate_password_hash(new_password)

    try:
        db.session.commit()
        flash('Contraseña cambiada exitosamente.', 'success')
        return redirect('/settings')
    except:
        flash('Error al cambiar la contraseña. Por favor, inténtalo de nuevo.', 'error')
        return redirect('/settings')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/actions', methods=['GET'])
@login_required
def actions():
    return send_from_directory('svelte-app/public', 'index.html')

@app.route("/<path:path>")
def home(path):
    return send_from_directory('svelte-app/public', path)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        quantity = request.form['quantity']
        description = request.form['description']
        total_price = float(request.form['total_price'])
        new_product = products(
            name=name, 
            quantity=quantity, 
            description=description, 
            total_price=total_price, 
            user_id=current_user.id  # Asignar el producto al usuario actual
        )

        try:
            db.session.add(new_product)
            db.session.commit()

            # Registro de historial con el precio inicial
            history_entry = productHistory(
                product_id=new_product.id,
                product_name=new_product.name,
                quantity=new_product.quantity,
                restocking_price=new_product.total_price  # Registrar el precio inicial
            )
            db.session.add(history_entry)
            db.session.commit()

            return redirect('/actions')
        except Exception as e:
            print(e)
            return 'ERROR ADDING PRODUCT: ' + str(e)
    else:
        return render_template('add_product.html')

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    task_to_delete = products.query.filter_by(id=id, user_id=current_user.id).first_or_404()

    try:
        # Marcamos el elemento como eliminado en lugar de eliminarlo
        task_to_delete.deleted = True
        db.session.commit()

        return redirect('/view_items')
    except Exception as e:
        return 'ERROR AL ELIMINAR: ' + str(e)


@app.route('/update_product/<int:id>', methods=['GET', 'POST'])
@login_required
def update_product(id):
    task = products.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        task.name = request.form['name']
        task.description = request.form['description']
        new_quantity = int(request.form['quantity'])
        new_total_price = float(request.form['total_price'])

        restocking_price = None
        if new_total_price != task.total_price:
            restocking_price = new_total_price

        task.quantity = new_quantity
        task.total_price = new_total_price

        try:
            db.session.commit()

            # Registro de historial
            history_entry = productHistory(
                product_id=task.id,
                product_name=task.name,
                quantity=new_quantity,
                restocking_price=restocking_price  # Solo se registra si hubo cambio en el precio
            )
            db.session.add(history_entry)
            db.session.commit()

            # Enviar alerta si la cantidad está por debajo del nivel de alerta
            if task.alert_quantity and task.quantity <= task.alert_quantity:
                send_alert_email(task)

            return redirect('/view_items')
        except Exception as e:
            return 'ERROR UPDATING PRODUCT: ' + str(e)
    else:
        return render_template('update_product.html', task=task)

def send_alert_email(task):
    user_email = current_user.email
    message = Mail(
        from_email='maldonadomaldonadoemmanuel227@gmail.com',
        to_emails=user_email,
        subject='Inventory Alert for {}'.format(task.name),
        html_content=f'The quantity for <strong>{task.name}</strong> has dropped to {task.quantity}, which is below your alert threshold of {task.alert_quantity}.'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))



@app.route('/view_items', methods=['GET'])
@login_required
def view_items():
    search_query = request.args.get('search')
    search_value = search_query.strip() if search_query else ''

    if search_value:
        # Filtrar los elementos por nombre usando una consulta que busca coincidencias parciales
        tasks = products.query.filter(
            products.name.ilike(f"%{search_value}%"),
            products.deleted == False,
            products.user_id == current_user.id  # Filtrar por el usuario actual
        ).order_by(products.date_created).all()
    else:
        # Si no hay consulta de búsqueda, obtener todos los elementos excluyendo los eliminados
        tasks = products.query.filter_by(
            deleted=False,
            user_id=current_user.id  # Filtrar por el usuario actual
        ).order_by(products.date_created).all()
    
    return render_template('view_items.html', tasks=tasks, search_value=search_value)

@app.route('/settings', methods=['GET'])
@login_required
def settings():
    return render_template('settings.html', current_user=current_user)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        db.session.delete(current_user)
        db.session.commit()
        flash('Your account has been deleted successfully.', 'success')
        return redirect('/login')
    except Exception as e:
        flash('An error occurred while deleting your account. Please try again.', 'error')
        return redirect('/settings')

# @app.route('/history_view', methods=['GET'])
# @login_required
# def history_view():
#     thirty_days_ago = datetime.utcnow() - timedelta(days=30)
#     history = ProductHistory.query.filter(ProductHistory.date >= thirty_days_ago).order_by(ProductHistory.date.desc()).all()
#     # history = ProductHistory.query.order_by(ProductHistory.date.desc()).all()
#     return render_template('history_view.html', history=history)

@app.route('/history_view')
@login_required
def history_view():
    # Obtener la suma de los precios de restocking para el mes actual
    monthly_expenditure = db.session.query(func.sum(productHistory.restocking_price)).filter(
        func.extract('month', productHistory.date) == datetime.now().month,
        func.extract('year', productHistory.date) == datetime.now().year
    ).scalar()

    # Si no hay registros para el mes actual, establecer la suma en 0
    if monthly_expenditure is None:
        monthly_expenditure = 0

    # Obtener el historial de productos
    history = productHistory.query.all()

    return render_template('history_view.html', history=history, monthly_expenditure=monthly_expenditure)

@app.route('/material_history/<int:product_id>', methods=['GET'])
@login_required
def product_history_view(product_id):
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    history = productHistory.query.filter(productHistory.product_id == product_id, productHistory.date >= thirty_days_ago).order_by(productHistory.date.asc()).all()

    # Calcular el gasto mensual
    monthly_expenditure = db.session.query(func.sum(productHistory.restocking_price)).filter(productHistory.product_id == product_id, productHistory.date >= thirty_days_ago).scalar()

    return render_template('material_history.html', history=history, monthly_expenditure=monthly_expenditure)

# @app.route('/material_history/<int:product_id>', methods=['GET'])
# @login_required
# def product_history_view(product_id):
#     thirty_days_ago = datetime.utcnow() - timedelta(days=30)
#     history = ProductHistory.query.filter(ProductHistory.product_id == product_id, ProductHistory.date >= thirty_days_ago).order_by(ProductHistory.date.asc()).all()
#     return render_template('material_history.html', history=history)

@app.route('/set_alert/<int:id>', methods=['GET', 'POST'])
@login_required
def set_alert(id):
    task = products.query.get_or_404(id)
    if request.method == 'POST':
        alert_quantity = request.form['alert_quantity']
        try:
            task.alert_quantity = int(alert_quantity)
            db.session.commit()
            flash('Alert quantity set successfully.', 'success')
            return redirect('/view_items')
        except Exception as e:
            flash('Error setting alert quantity. Please try again.', 'error')
            return redirect('/set_alert/{}'.format(id))
    else:
        return render_template('set_alert.html', task=task)

# @app.route('/update_quantity/<int:id>', methods=['POST'])
# @login_required
# def update_quantity(id):
#     data = request.get_json()
#     new_quantity = data.get('quantity')

#     if new_quantity is not None:
#         try:
#             new_quantity = int(new_quantity)  # Convertir a entero
#             if new_quantity < 0:
#                 raise ValueError("Quantity cannot be negative")
            
#             task = to_do.query.get_or_404(id)
#             task.quantity = new_quantity
#             db.session.commit()
#             return jsonify(success=True, message="Quantity updated successfully"), 200
#         except ValueError as ve:
#             return jsonify(success=False, error="Invalid quantity"), 400
#         except Exception as e:
#             db.session.rollback()  # Revertir cambios en caso de error
#             return jsonify(success=False, error=str(e)), 500
#     else:
#         return jsonify(success=False, error="Invalid quantity"), 400

@app.route('/update_quantity/<int:task_id>', methods=['POST'])
@login_required
def update_quantity(task_id):
    data = request.get_json()
    new_quantity = data.get('quantity')

    task = products.query.get_or_404(task_id)
    original_quantity = task.quantity
    task.quantity = new_quantity

    try:
        db.session.commit()

        # Verificar si la cantidad está por debajo del umbral de alerta
        if task.alert_quantity is not None and new_quantity <= task.alert_quantity:
            send_alert_email(task)

        # Registrar la actualización en el historial de productos
        history_entry = productHistory(
            product_id=task.id,
            product_name=task.name,
            quantity=new_quantity,
            restocking_price=None  # No hay cambio en el precio de reabastecimiento
        )
        db.session.add(history_entry)
        db.session.commit()

        return jsonify({'message': 'Quantity updated successfully!'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to update quantity.', 'error': str(e)}), 500

def send_alert_email(task):
    user_email = current_user.email
    message = Mail(
        from_email='maldonadomaldonadoemmanuel227@gmail.com',
        to_emails=user_email,
        subject='Low Inventory Alert',
        html_content=f'The quantity of the product "{task.name}" is below the alert threshold. Current quantity: {task.quantity}'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

if __name__ == "__main__":
    app.run(debug=True)
