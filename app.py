from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
import json
import re
import time
import hashlib
import os

app = Flask(__name__)

# ════ SECURITY CONFIG ════

app.secret_key = 'raheeb-secret-key-2026-fixed'        
app.config['SQLALCHEMY_DATABASE_URI']    = 'sqlite:///orders.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

db = SQLAlchemy(app)

# ════ ADMIN CREDENTIALS ════
ADMIN_USER      = 'raheeb'
ADMIN_PASS_HASH = hashlib.sha256('raheeb2026'.encode()).hexdigest()

# ════ RATE LIMITING ════
login_attempts  = {}
order_attempts  = {}

MAX_LOGIN_ATTEMPTS = 5
MAX_ORDERS_PER_HR  = 10
BLOCK_MINUTES      = 15

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def is_rate_limited(store, ip, max_attempts, window_minutes):
    now     = time.time()
    window  = window_minutes * 60
    if ip not in store:
        store[ip] = []
    store[ip] = [t for t in store[ip] if now - t < window]
    if len(store[ip]) >= max_attempts:
        return True
    store[ip].append(now)
    return False

# ════ SECURITY HEADERS ════
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']          = 'DENY'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy']  = (
        "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;"
    )
    return response

# ════ INPUT SANITIZATION ════
def sanitize(text, max_len=200):
    if not isinstance(text, str):
        return ''
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'[<>"\';\\]', '', text)
    return text.strip()[:max_len]

def validate_phone(phone):
    phone = re.sub(r'\s', '', phone)
    return bool(re.match(r'^(0)(5|6|7)\d{8}$', phone))

# ════ ADMIN DECORATOR ════
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login_page'))
        return f(*args, **kwargs)
    return decorated

# ════ DATABASE MODEL ════
class Order(db.Model):
    id         = db.Column(db.Integer,  primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    phone      = db.Column(db.String(20),  nullable=False)
    wilaya     = db.Column(db.String(50),  nullable=False)
    commune    = db.Column(db.String(50),  nullable=False)
    address    = db.Column(db.String(200), nullable=False)
    items      = db.Column(db.Text,        nullable=False)
    total      = db.Column(db.Float,       nullable=False)
    status     = db.Column(db.String(20),  default='new')
    ip_address = db.Column(db.String(50),  nullable=True)   
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':         self.id,
            'name':       self.name,
            'phone':      self.phone,
            'wilaya':     self.wilaya,
            'commune':    self.commune,
            'address':    self.address,
            'items':      json.loads(self.items),
            'total':      self.total,
            'status':     self.status,
            'ip_address': self.ip_address,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M')
        }

with app.app_context():
    db.create_all()

# ════ CUSTOMER ROUTES ════
@app.route('/')
def index():
    return render_template('index.html')   # الصفحة الرئيسية الجديدة

@app.route('/order')
def order_page():
    return render_template('order.html')   # صفحة الطلب القديمة

@app.route('/api/order', methods=['POST'])
def place_order():
    ip = get_ip()

    if is_rate_limited(order_attempts, ip, MAX_ORDERS_PER_HR, 60):
        return jsonify({'success': False, 'message': 'تجاوزت الحد المسموح، حاول بعد ساعة'}), 429

    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'بيانات غير صحيحة'}), 400

    required = ['name', 'phone', 'wilaya', 'commune', 'address', 'items', 'total']
    for f in required:
        if f not in data or not data[f]:
            return jsonify({'success': False, 'message': f'حقل مفقود: {f}'}), 400

    name    = sanitize(data['name'],    max_len=100)
    phone   = sanitize(data['phone'],   max_len=20)
    wilaya  = sanitize(data['wilaya'],  max_len=50)
    commune = sanitize(data['commune'], max_len=50)
    address = sanitize(data['address'], max_len=200)
    
    if not name or len(name) < 2:
        return jsonify({'success': False, 'message': 'الاسم غير صحيح'}), 400

    if not validate_phone(phone):
        return jsonify({'success': False, 'message': 'رقم الهاتف غير صحيح'}), 400

    items = data.get('items', [])
    if not isinstance(items, list) or len(items) == 0 or len(items) > 50:
        return jsonify({'success': False, 'message': 'الطلبات غير صحيحة'}), 400

    try:
        total = float(data['total'])
        if total <= 0 or total > 100000:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'الإجمالي غير صحيح'}), 400

    order = Order(
        name       = name,
        phone      = phone,
        wilaya     = wilaya,
        commune    = commune,
        address    = address,
        items      = json.dumps(items, ensure_ascii=False),
        total      = total,
        ip_address = ip
    )
    db.session.add(order)
    db.session.commit()

    return jsonify({'success': True, 'order_id': order.id})

# ════ ADMIN ROUTES ════
@app.route('/admin')
def admin_login_page():
    if session.get('admin'):
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    ip = get_ip()

    if ip in login_attempts:
        now = time.time()
        login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BLOCK_MINUTES * 60]
        if len(login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS:
            return render_template('admin_login.html',
                error=f'تم حظرك مؤقتاً لمدة {BLOCK_MINUTES} دقيقة بسبب كثرة المحاولات الخاطئة')

    u = sanitize(request.form.get('username', ''))
    p = request.form.get('password', '')
    p_hash = hashlib.sha256(p.encode()).hexdigest()

    time.sleep(0.5)

    if u == ADMIN_USER and p_hash == ADMIN_PASS_HASH:
        session.permanent = True
        session['admin']  = True
        session['login_time'] = datetime.utcnow().isoformat()
        login_attempts.pop(ip, None)
        return redirect(url_for('admin_dashboard'))

    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(now)

    return render_template('admin_login.html', error='اسم المستخدم أو كلمة المرور خاطئة')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login_page'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/api/orders')
@admin_required
def api_orders():
    status_filter = request.args.get('status', 'all')
    if status_filter not in ['all', 'new', 'preparing', 'delivered']:
        return jsonify({'error': 'Invalid filter'}), 400
    if status_filter == 'all':
        orders = Order.query.order_by(Order.created_at.desc()).all()
    else:
        orders = Order.query.filter_by(status=status_filter).order_by(Order.created_at.desc()).all()
    return jsonify([o.to_dict() for o in orders])

@app.route('/admin/api/order/<int:order_id>/status', methods=['POST'])
@admin_required
def update_status(order_id):
    order = Order.query.get_or_404(order_id)
    data  = request.get_json()
    new_status = data.get('status', '')
    if new_status not in ['new', 'preparing', 'delivered']:
        return jsonify({'error': 'Invalid status'}), 400
    order.status = new_status
    db.session.commit()
    return jsonify({'success': True})

# ════ BACKUP ════
@app.route('/admin/backup')
@admin_required
def backup_db():
    from flask import send_file
    import shutil
    backup_path = f'orders_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    shutil.copy('orders.db', backup_path)
    return send_file(backup_path, as_attachment=True)

# ════ منع الوصول لملفات حساسة ════
@app.route('/orders.db')
@app.route('/app.py')
@app.route('/requirements.txt')
def block_sensitive_files():
    abort(403)