# app.py - NBN Enterprise Management System
# Complete production-ready build: security, error handling, race conditions fixed,
# input validation, export, audit trail, pagination, session timeout, rate limiting

import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import hashlib
import io
import base64
import random
import string
import time
import re
import os
from contextlib import contextmanager
from streamlit_option_menu import option_menu

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NBN Enterprise Management System",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = 'nbn_enterprise.db'
SESSION_TIMEOUT_MINUTES = 60
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

# ─────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    .main { padding: 0rem 1rem; }
    .custom-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem; border-radius: 1rem; color: white; margin-bottom: 1rem;
    }
    .metric-card {
        background: white; padding: 1rem; border-radius: 0.5rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #b91c1c;
        margin-bottom: 1rem; transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 20px 25px -5px rgba(185, 28, 28, 0.1);
    }
    .status-badge {
        display: inline-block; padding: 0.25rem 0.75rem;
        border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
    }
    .status-active   { background: #d1fae5; color: #065f46; }
    .status-pending  { background: #fed7aa; color: #92400e; }
    .status-inactive { background: #fee2e2; color: #b91c1c; }
    .status-completed{ background: #dbeafe; color: #1e40af; }
    .stButton > button { border-radius: 0.5rem; transition: all 0.3s; }
    .stButton > button:hover { transform: translateY(-2px); }
    .dataframe { font-size: 0.9rem; }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: #f1f1f1; border-radius: 10px; }
    ::-webkit-scrollbar-thumb { background: #b91c1c; border-radius: 10px; }
    .progress-bar { height: 8px; border-radius: 4px; background: #e5e7eb; overflow: hidden; }
    .progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s ease; }
    div[data-testid="stForm"] {
        background-color: #f9fafb; padding: 1.5rem;
        border-radius: 0.5rem; border: 1px solid #e5e7eb;
    }
    .toast-success {
        background: #d1fae5; color: #065f46; padding: 0.75rem 1rem;
        border-radius: 0.5rem; border-left: 4px solid #10b981;
        margin-bottom: 0.5rem; font-weight: 500;
    }
    .toast-error {
        background: #fee2e2; color: #b91c1c; padding: 0.75rem 1rem;
        border-radius: 0.5rem; border-left: 4px solid #ef4444;
        margin-bottom: 0.5rem; font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────
_defaults = {
    'page': 'login',
    'logged_in': False,
    'user': None,
    'order_items': [],
    'login_error': None,
    'login_attempts': {},       # {username: [timestamp, ...]}
    'last_activity': None,
    'toast': None,              # {'type': 'success'|'error', 'msg': str}
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
def show_toast(msg, kind='success'):
    """Queue a toast notification rendered at the top of the next render."""
    st.session_state.toast = {'type': kind, 'msg': msg}


def render_toast():
    t = st.session_state.get('toast')
    if t:
        css_class = 'toast-success' if t['type'] == 'success' else 'toast-error'
        icon = '✅' if t['type'] == 'success' else '❌'
        st.markdown(f"<div class='{css_class}'>{icon} {t['msg']}</div>", unsafe_allow_html=True)
        st.session_state.toast = None


def check_session_timeout():
    """Auto-logout after SESSION_TIMEOUT_MINUTES of inactivity."""
    if st.session_state.logged_in:
        last = st.session_state.last_activity
        if last and (datetime.now() - last).total_seconds() > SESSION_TIMEOUT_MINUTES * 60:
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.page = 'login'
            st.session_state.order_items = []
            show_toast("Session expired. Please log in again.", 'error')
            st.rerun()
        st.session_state.last_activity = datetime.now()


def is_rate_limited(username):
    """Return True if the user is locked out due to too many failed attempts."""
    attempts = st.session_state.login_attempts.get(username, [])
    cutoff = datetime.now() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
    recent = [t for t in attempts if t > cutoff]
    st.session_state.login_attempts[username] = recent
    return len(recent) >= MAX_LOGIN_ATTEMPTS


def record_failed_attempt(username):
    attempts = st.session_state.login_attempts.get(username, [])
    attempts.append(datetime.now())
    st.session_state.login_attempts[username] = attempts


def clear_failed_attempts(username):
    st.session_state.login_attempts.pop(username, None)


# ─────────────────────────────────────────────
# DB CONTEXT MANAGER
# ─────────────────────────────────────────────
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row  # Fix: enable column-name access on all cursors
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# DATABASE INIT
# ─────────────────────────────────────────────
def init_database():
    with get_db() as conn:
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP,
            used BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            permission TEXT NOT NULL,
            UNIQUE(role, permission)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            cost REAL,
            stock_quantity INTEGER DEFAULT 0,
            min_stock INTEGER DEFAULT 0,
            unit TEXT DEFAULT 'units',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS inventory_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            transaction_type TEXT,
            quantity INTEGER,
            reason TEXT,
            transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            city TEXT,
            customer_type TEXT,
            status TEXT DEFAULT 'active',
            total_spent REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_number TEXT UNIQUE NOT NULL,
            customer_id INTEGER,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            payment_method TEXT,
            payment_status TEXT DEFAULT 'pending',
            subtotal REAL DEFAULT 0,
            tax REAL DEFAULT 0,
            total REAL DEFAULT 0,
            notes TEXT,
            created_by INTEGER,
            FOREIGN KEY (customer_id) REFERENCES customers (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            unit_price REAL,
            total REAL,
            FOREIGN KEY (order_id) REFERENCES orders (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS production_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            batch_number TEXT NOT NULL,
            shift TEXT,
            operator TEXT,
            quantity REAL,
            produced_date DATE,
            status TEXT DEFAULT 'completed',
            quality_score REAL,
            notes TEXT,
            recorded_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products (id),
            FOREIGN KEY (recorded_by) REFERENCES users (id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS machines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT,
            status TEXT DEFAULT 'idle',
            current_batch TEXT,
            speed TEXT,
            efficiency REAL DEFAULT 0,
            last_maintenance DATE,
            next_maintenance DATE
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS financial_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_type TEXT CHECK(transaction_type IN ('revenue', 'expense')),
            category TEXT,
            amount REAL NOT NULL,
            description TEXT,
            transaction_date DATE NOT NULL,
            reference TEXT,
            order_id INTEGER,
            status TEXT DEFAULT 'completed',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES orders (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )''')

        # Indexes for performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(order_date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_products_category ON products(category)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ft_type_date ON financial_transactions(transaction_type, transaction_date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_inventory_tx_product ON inventory_transactions(product_id)")

        # Permissions
        permissions = [
            ('admin', 'view_dashboard'), ('admin', 'manage_products'), ('admin', 'manage_inventory'),
            ('admin', 'manage_customers'), ('admin', 'manage_orders'), ('admin', 'manage_production'),
            ('admin', 'manage_financials'), ('admin', 'view_reports'), ('admin', 'manage_users'),
            ('admin', 'manage_settings'), ('admin', 'view_activity_logs'),
            ('manager', 'view_dashboard'), ('manager', 'manage_products'), ('manager', 'manage_inventory'),
            ('manager', 'manage_customers'), ('manager', 'manage_orders'), ('manager', 'manage_production'),
            ('manager', 'view_reports'),
            ('financial', 'view_dashboard'), ('financial', 'manage_financials'), ('financial', 'view_reports'),
            ('production', 'view_dashboard'), ('production', 'manage_production'), ('production', 'view_reports'),
            ('sales', 'view_dashboard'), ('sales', 'manage_customers'), ('sales', 'manage_orders'),
            ('viewer', 'view_dashboard')
        ]
        for role, perm in permissions:
            c.execute("INSERT OR IGNORE INTO role_permissions (role, permission) VALUES (?, ?)", (role, perm))

        # Default system settings
        defaults = [
            ('company_name', 'NBN Enterprise'),
            ('company_logo', '🏭'),
            ('primary_color', '#b91c1c'),
            ('secondary_color', '#fbbf24'),
            ('system_name', 'NBN Enterprise Management System'),
            ('login_background', 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)')
        ]
        for k, v in defaults:
            c.execute("INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES (?, ?)", (k, v))

        # Default admin
        c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if c.fetchone()[0] == 0:
            admin_pw = hash_password('admin123')
            c.execute("""INSERT INTO users (username, password, email, full_name, role, is_active)
                         VALUES (?, ?, ?, ?, ?, ?)""",
                      ('admin', admin_pw, 'admin@nbn.com', 'System Administrator', 'admin', 1))
            sample_users = [
                ('finance_manager',    hash_password('finance123'),    'finance@nbn.com',    'Finance Manager',    'financial', 1),
                ('production_manager', hash_password('production123'), 'production@nbn.com', 'Production Manager', 'production', 1),
                ('sales_manager',      hash_password('sales123'),      'sales@nbn.com',      'Sales Manager',      'sales', 1),
                ('viewer_user',        hash_password('viewer123'),     'viewer@nbn.com',     'Viewer User',        'viewer', 1),
            ]
            for u in sample_users:
                c.execute("INSERT OR IGNORE INTO users (username, password, email, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?)", u)

        # Sample products
        c.execute("SELECT COUNT(*) FROM products")
        if c.fetchone()[0] == 0:
            products = [
                ('TS-101', 'Tissue Roll Premium',  'Tissue',       45.50,  28.00,  430, 50, 'roll',  'Premium quality tissue roll'),
                ('TS-102', 'Tissue Jumbo Roll',    'Tissue',       320.00, 210.00, 12,  20, 'roll',  'Jumbo size for commercial use'),
                ('RF-205', 'Roofing Sheet 8ft',    'Roofing',      78.90,  52.00,  87,  30, 'sheet', 'Standard 8ft roofing sheet'),
                ('RF-207', 'Roofing Sheet 10ft',   'Roofing',      94.50,  63.00,  86,  30, 'sheet', 'Standard 10ft roofing sheet'),
                ('AC-300', 'Roofing Nails',        'Accessory',    28.00,  18.00,  200, 20, 'kg',    'Galvanized roofing nails'),
                ('RM-001', 'Raw Pulp',             'Raw Material', 1500.00,1100.00, 4,  10, 'ton',   'Industrial raw pulp'),
            ]
            for p in products:
                c.execute("INSERT INTO products (sku, name, category, price, cost, stock_quantity, min_stock, unit, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", p)

            customers = [
                ('CUST001', 'ABC Builders',     'john@abc.com',   '0241234567', 'Independence Avenue', 'Accra',  'Contractor',  'active', 156800),
                ('CUST002', 'XYZ Construction', 'kwame@xyz.com',  '0278901234', 'Ahodwo',              'Kumasi', 'Contractor',  'active', 98450),
                ('CUST003', 'PQR Industries',   'abena@pqr.com',  '0205678901', 'Industrial Area',     'Tema',   'Distributor', 'active', 234600),
            ]
            for cust in customers:
                c.execute("INSERT INTO customers (customer_code, name, email, phone, address, city, customer_type, status, total_spent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", cust)

            machines = [
                ('Tissue Line A',  'Tissue',    'running',     'T-0424', '120 units/min', 94, '2026-04-01', '2026-04-15'),
                ('Roofing Line B', 'Roofing',   'running',     'R-0425', '45 units/min',  88, '2026-04-02', '2026-04-16'),
                ('Tissue Line C',  'Tissue',    'maintenance', None,     '110 units/min', 76, '2026-03-20', '2026-04-05'),
                ('Packaging Line', 'Packaging', 'idle',        None,     '60 units/min',  92, '2026-04-03', '2026-04-17'),
            ]
            for m in machines:
                c.execute("INSERT INTO machines (name, type, status, current_batch, speed, efficiency, last_maintenance, next_maintenance) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", m)

            financials = [
                ('revenue', 'Sales',        145000, 'Monthly tissue sales',  '2026-03-31', 'REV-001', None),
                ('revenue', 'Sales',        89000,  'Monthly roofing sales', '2026-03-31', 'REV-002', None),
                ('expense', 'Raw Materials',55000,  'Pulp purchase',         '2026-03-25', 'EXP-001', None),
                ('expense', 'Labor',        62000,  'Monthly salaries',      '2026-03-28', 'EXP-002', None),
            ]
            for f in financials:
                c.execute("INSERT INTO financial_transactions (transaction_type, category, amount, description, transaction_date, reference, order_id) VALUES (?, ?, ?, ?, ?, ?, ?)", f)


# ─────────────────────────────────────────────
# VALIDATION HELPERS
# ─────────────────────────────────────────────
def validate_email(email):
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email)) if email else True

def validate_phone(phone):
    return bool(re.match(r'^[\d\s\+\-\(\)]{7,15}$', phone)) if phone else True

def validate_password(password):
    """Returns (ok, message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, ""


# ─────────────────────────────────────────────
# AUTH & SECURITY
# ─────────────────────────────────────────────
def hash_password(password):
    salt = "nbn_enterprise_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def log_activity(user_id, action, details=""):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO user_activity (user_id, action, details) VALUES (?, ?, ?)",
                (user_id, action, str(details)[:500])
            )
    except Exception as e:
        print(f"Activity log error: {e}")

def get_system_setting(key):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT setting_value FROM system_settings WHERE setting_key = ?", (key,)).fetchone()
        return row[0] if row else None
    except Exception:
        return None

def update_system_setting(key, value):
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE system_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = ?",
                (value, key)
            )
        return True
    except Exception as e:
        print(f"Setting update error: {e}")
        return False

def backup_database():
    """Create a timestamped SQLite file backup in the backups/ folder."""
    import shutil
    backup_dir = 'backups'
    try:
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        if not os.path.exists(DB_PATH):
            return "Error: Database file not found."
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f'nbn_enterprise_backup_{timestamp}.db')
        shutil.copy2(DB_PATH, backup_path)
        return f"Backup created at {backup_path}"
    except PermissionError as e:
        return f"Error: Permission denied - {e}"
    except Exception as e:
        return f"Error creating backup: {e}"


# All tables in dependency order (parents before children)
_ALL_TABLES = [
    'system_settings',
    'users',
    'role_permissions',
    'password_resets',
    'user_activity',
    'customers',
    'products',
    'inventory_transactions',
    'orders',
    'order_items',
    'machines',
    'production_records',
    'financial_transactions',
]

# SQLite → target dialect type mappings
_TYPE_MAP = {
    'postgresql': {
        'INTEGER':   'INTEGER',
        'REAL':      'DOUBLE PRECISION',
        'TEXT':      'TEXT',
        'BOOLEAN':   'BOOLEAN',
        'TIMESTAMP': 'TIMESTAMP',
        'DATE':      'DATE',
        'AUTOINCREMENT': 'GENERATED ALWAYS AS IDENTITY',
    },
    'mysql': {
        'INTEGER':   'INT',
        'REAL':      'DOUBLE',
        'TEXT':      'LONGTEXT',
        'BOOLEAN':   'TINYINT(1)',
        'TIMESTAMP': 'DATETIME',
        'DATE':      'DATE',
        'AUTOINCREMENT': 'AUTO_INCREMENT',
    },
}


def _sqlite_val_to_sql(val):
    """Convert a Python value to a SQL literal safe for embedding in INSERT."""
    if val is None:
        return 'NULL'
    if isinstance(val, (int, float)):
        return str(val)
    escaped = str(val).replace("'", "''")
    return f"'{escaped}'"


def _get_create_ddl(conn, table):
    """Return the original CREATE TABLE statement from sqlite_master."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row[0] if row else None


def _translate_ddl(ddl, dialect):
    """Translate a SQLite CREATE TABLE statement to PostgreSQL or MySQL syntax."""
    if dialect == 'sqlite':
        return ddl + ';'

    mapping = _TYPE_MAP[dialect]
    result = ddl

    # Swap AUTOINCREMENT keyword first (before INTEGER replacement)
    if dialect == 'postgresql':
        # PostgreSQL uses SERIAL or IDENTITY; we'll use SERIAL for simplicity
        result = re.sub(
            r'(\w+)\s+INTEGER\s+PRIMARY KEY\s+AUTOINCREMENT',
            r'\1 INTEGER PRIMARY KEY ' + mapping['AUTOINCREMENT'],
            result, flags=re.IGNORECASE
        )
        # Remaining type swaps
        for sqlite_t, pg_t in [
            ('BOOLEAN', mapping['BOOLEAN']),
            ('TIMESTAMP', mapping['TIMESTAMP']),
            ('DATE', mapping['DATE']),
            ('REAL', mapping['REAL']),
            ('TEXT', mapping['TEXT']),
            ('INTEGER', mapping['INTEGER']),
        ]:
            result = re.sub(r'\b' + sqlite_t + r'\b', pg_t, result, flags=re.IGNORECASE)
        # Remove inline CHECK constraints not portable
        result = re.sub(r"\s*CHECK\s*\([^)]*\)", '', result, flags=re.IGNORECASE)

    elif dialect == 'mysql':
        result = re.sub(
            r'(\w+)\s+INTEGER\s+PRIMARY KEY\s+AUTOINCREMENT',
            r'\1 INT PRIMARY KEY ' + mapping['AUTOINCREMENT'],
            result, flags=re.IGNORECASE
        )
        for sqlite_t, my_t in [
            ('BOOLEAN', mapping['BOOLEAN']),
            ('TIMESTAMP', mapping['TIMESTAMP']),
            ('DATE', mapping['DATE']),
            ('REAL', mapping['REAL']),
            ('TEXT', mapping['TEXT']),
            ('INTEGER', mapping['INTEGER']),
        ]:
            result = re.sub(r'\b' + sqlite_t + r'\b', my_t, result, flags=re.IGNORECASE)
        # MySQL: CURRENT_TIMESTAMP default is fine; remove SQLite-only pragmas
        result = re.sub(r"\s*CHECK\s*\([^)]*\)", '', result, flags=re.IGNORECASE)
        # Wrap in ENGINE clause
        result = result.rstrip().rstrip(')') + '\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'

    return result + ';\n'


def _build_insert_block(conn, table, dialect):
    """Return INSERT statements for all rows in a table."""
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
    if not rows:
        return ''
    cols = [d[0] for d in conn.execute(f"SELECT * FROM {table} LIMIT 0").description]  # noqa: S608
    col_list = ', '.join(f'"{c}"' for c in cols)
    lines = []
    for row in rows:
        vals = ', '.join(_sqlite_val_to_sql(v) for v in row)
        lines.append(f'INSERT INTO "{table}" ({col_list}) VALUES ({vals});')
    return '\n'.join(lines) + '\n'


def export_backup_sql(dialect='sqlite'):
    """
    Generate a complete SQL dump for the given dialect ('sqlite', 'postgresql', 'mysql').
    Returns (sql_string, error_string).  One of the two will be None.
    """
    dialect = dialect.lower()
    if dialect not in ('sqlite', 'postgresql', 'mysql'):
        return None, f"Unknown dialect '{dialect}'"

    if not os.path.exists(DB_PATH):
        return None, "Database file not found."

    try:
        parts = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Header comment
        parts.append(f"-- NBN Enterprise — {dialect.upper()} backup")
        parts.append(f"-- Generated: {ts}")
        parts.append(f"-- Tables: {', '.join(_ALL_TABLES)}\n")

        if dialect == 'mysql':
            parts.append("SET FOREIGN_KEY_CHECKS = 0;")
            parts.append("SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';")
            parts.append("SET NAMES utf8mb4;\n")
        elif dialect == 'postgresql':
            parts.append("SET client_encoding = 'UTF8';")
            parts.append("SET standard_conforming_strings = on;\n")

        with sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True, timeout=30) as conn:
            conn.row_factory = sqlite3.Row
            for table in _ALL_TABLES:
                ddl = _get_create_ddl(conn, table)
                if not ddl:
                    continue  # table may not exist yet

                parts.append(f"\n-- ──────────────────────────────")
                parts.append(f"-- Table: {table}")
                parts.append(f"-- ──────────────────────────────")

                if dialect == 'mysql':
                    parts.append(f'DROP TABLE IF EXISTS `{table}`;')
                elif dialect == 'postgresql':
                    parts.append(f'DROP TABLE IF EXISTS "{table}" CASCADE;')
                else:
                    parts.append(f'DROP TABLE IF EXISTS "{table}";')

                parts.append(_translate_ddl(ddl, dialect))
                parts.append(_build_insert_block(conn, table, dialect))

        if dialect == 'mysql':
            parts.append("\nSET FOREIGN_KEY_CHECKS = 1;")

        parts.append(f"\n-- End of backup — {ts}")
        return '\n'.join(parts), None

    except Exception as e:
        return None, f"Export failed: {e}"


def export_backup_sqlite_file():
    """
    Binary copy of the SQLite file.  Returns (bytes, filename, error).
    """
    if not os.path.exists(DB_PATH):
        return None, None, "Database file not found."
    try:
        import shutil, io as _io
        buf = _io.BytesIO()
        with open(DB_PATH, 'rb') as f:
            buf.write(f.read())
        buf.seek(0)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"nbn_enterprise_backup_{ts}.db"
        return buf.getvalue(), fname, None
    except Exception as e:
        return None, None, f"Export failed: {e}"



def get_user_role(user_id):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        return row[0] if row else None
    except Exception:
        return None

def has_permission(user_id, permission):
    role = get_user_role(user_id)
    if not role:
        return False
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM role_permissions WHERE role = ? AND permission = ?",
                (role, permission)
            ).fetchone()
        return row[0] > 0
    except Exception:
        return False

def login_user(username, password):
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, password, email, full_name, role, is_active FROM users WHERE username = ?",
                (username,)
            ).fetchone()
    except Exception:
        return None

    if row and verify_password(password, row[2]) and row[6] == 1:
        try:
            with get_db() as conn:
                conn.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (row[0],))
        except Exception:
            pass
        log_activity(row[0], "login", f"User {username} logged in")
        return {'id': row[0], 'username': row[1], 'email': row[3], 'full_name': row[4], 'role': row[5]}
    return None

def get_all_users():
    try:
        with get_db() as conn:
            df = pd.read_sql_query(
                "SELECT id, username, email, full_name, role, is_active, last_login, created_at FROM users ORDER BY created_at",
                conn
            )
        return df
    except Exception:
        return pd.DataFrame()

def add_user(username, password, email, full_name, role, created_by):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password, email, full_name, role, is_active, created_by) VALUES (?, ?, ?, ?, ?, 1, ?)",
                (username.strip(), hash_password(password), email.strip(), full_name.strip(), role, created_by)
            )
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        log_activity(created_by, "create_user", f"Created user {username} with role {role}")
        return True, user_id
    except sqlite3.IntegrityError:
        return False, None
    except Exception as e:
        print(f"Add user error: {e}")
        return False, None

def update_user(user_id, email, full_name, role, is_active, admin_id):
    try:
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET email = ?, full_name = ?, role = ?, is_active = ? WHERE id = ?",
                (email, full_name, role, is_active, user_id)
            )
        log_activity(admin_id, "update_user", f"Updated user ID {user_id}")
        return True
    except Exception as e:
        print(f"Update user error: {e}")
        return False

def delete_user(user_id, admin_id):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
        log_activity(admin_id, "delete_user", f"Deleted user ID {user_id}")
        return True
    except Exception as e:
        print(f"Delete user error: {e}")
        return False

def change_user_password(user_id, new_password, admin_id=None):
    try:
        with get_db() as conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(new_password), user_id))
        if admin_id:
            log_activity(admin_id, "reset_password", f"Reset password for user ID {user_id}")
        return True
    except Exception:
        return False

def get_user_activity_log(limit=100):
    try:
        with get_db() as conn:
            df = pd.read_sql_query(
                """SELECT ua.id, u.username, ua.action, ua.details, ua.timestamp
                   FROM user_activity ua
                   JOIN users u ON ua.user_id = u.id
                   ORDER BY ua.timestamp DESC LIMIT ?""",
                conn, params=(limit,)
            )
        return df
    except Exception:
        return pd.DataFrame()


# ─────────────────────────────────────────────
# BUSINESS FUNCTIONS
# ─────────────────────────────────────────────
def generate_sku(category):
    prefix_map = {'Tissue': 'TS', 'Roofing': 'RF', 'Accessory': 'AC', 'Raw Material': 'RM'}
    prefix = prefix_map.get(category, 'PR')
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT sku FROM products WHERE sku LIKE ?", (f'{prefix}-%',)).fetchall()
        if rows:
            numbers = []
            for r in rows:
                parts = r[0].split('-')
                if len(parts) >= 2 and parts[1].isdigit():
                    numbers.append(int(parts[1]))
            next_num = (max(numbers) + 1) if numbers else 101
        else:
            next_num = 101
        return f"{prefix}-{next_num:03d}"
    except Exception:
        return f"{prefix}-{random.randint(100, 999)}"

def generate_order_number():
    date_str = datetime.now().strftime('%Y%m%d')
    try:
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) FROM orders WHERE order_number LIKE ?", (f'ORD-{date_str}-%',)).fetchone()
        count = row[0] if row else 0
        return f"ORD-{date_str}-{count + 1:04d}"
    except Exception:
        return f"ORD-{date_str}-{random.randint(1000,9999)}"

def generate_customer_code():
    try:
        with get_db() as conn:
            # Use MAX on the numeric suffix to avoid duplicates from COUNT on concurrent inserts
            row = conn.execute(
                "SELECT MAX(CAST(SUBSTR(customer_code, 5) AS INTEGER)) FROM customers WHERE customer_code LIKE 'CUST%'"
            ).fetchone()
        max_num = row[0] if row and row[0] is not None else 0
        return f"CUST{max_num + 1:04d}"
    except Exception:
        return f"CUST{random.randint(1000,9999)}"

def get_products(search=None, category=None):
    try:
        query = "SELECT id, sku, name, category, price, cost, stock_quantity, min_stock, unit FROM products WHERE 1=1"
        params = []
        if search:
            query += " AND (name LIKE ? OR sku LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        if category and category != "All Categories":
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY name"
        with get_db() as conn:
            df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as e:
        print(f"Get products error: {e}")
        return pd.DataFrame()

def add_product(name, category, price, cost, stock, min_stock, unit, description, user_id):
    try:
        sku = generate_sku(category)
        with get_db() as conn:
            conn.execute(
                """INSERT INTO products (sku, name, category, price, cost, stock_quantity, min_stock, unit, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sku, name.strip(), category, float(price), float(cost), int(stock), int(min_stock), unit.strip(), description.strip())
            )
        log_activity(user_id, "add_product", f"Added product {name} SKU {sku}")
        return True, sku
    except Exception as e:
        print(f"Add product error: {e}")
        return False, None

def update_product(product_id, name, category, price, cost, stock, min_stock, unit, description, user_id):
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE products SET name=?, category=?, price=?, cost=?,
                   stock_quantity=?, min_stock=?, unit=?, description=?, updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (name.strip(), category, float(price), float(cost), int(stock), int(min_stock), unit.strip(), description, product_id)
            )
        log_activity(user_id, "update_product", f"Updated product ID {product_id}")
        return True
    except Exception as e:
        print(f"Update product error: {e}")
        return False

def delete_product(product_id, user_id):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM products WHERE id=?", (product_id,))
        log_activity(user_id, "delete_product", f"Deleted product ID {product_id}")
        return True
    except Exception as e:
        print(f"Delete product error: {e}")
        return False

def get_customers(search=None, status=None):
    try:
        query = "SELECT id, customer_code, name, email, phone, city, customer_type, status, total_spent FROM customers WHERE 1=1"
        params = []
        if search:
            query += " AND (name LIKE ? OR customer_code LIKE ? OR email LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        if status and status != "All":
            query += " AND status = ?"
            params.append(status.lower())
        query += " ORDER BY name"
        with get_db() as conn:
            df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as e:
        print(f"Get customers error: {e}")
        return pd.DataFrame()

def add_customer(name, email, phone, address, city, customer_type, status, user_id):
    try:
        code = generate_customer_code()
        with get_db() as conn:
            conn.execute(
                "INSERT INTO customers (customer_code, name, email, phone, address, city, customer_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (code, name.strip(), email.strip(), phone.strip(), address.strip(), city.strip(), customer_type, status)
            )
        log_activity(user_id, "add_customer", f"Added customer {name} code {code}")
        return True, code
    except Exception as e:
        print(f"Add customer error: {e}")
        return False, None

def update_customer(customer_id, name, email, phone, address, city, customer_type, status, user_id):
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE customers SET name=?, email=?, phone=?, address=?, city=?, customer_type=?, status=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (name, email, phone, address, city, customer_type, status, customer_id)
            )
        log_activity(user_id, "update_customer", f"Updated customer ID {customer_id}")
        return True
    except Exception as e:
        print(f"Update customer error: {e}")
        return False

def delete_customer(customer_id, user_id):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM customers WHERE id=?", (customer_id,))
        log_activity(user_id, "delete_customer", f"Deleted customer ID {customer_id}")
        return True
    except Exception as e:
        print(f"Delete customer error: {e}")
        return False

def add_order(customer_id, items, payment_method, notes, user_id):
    """
    Creates order with stock check inside a single transaction to prevent race conditions.
    Raises ValueError if stock is insufficient.
    """
    order_number = generate_order_number()
    subtotal = sum(item['total'] for item in items)
    tax = subtotal * 0.125
    total = subtotal + tax

    try:
        with get_db() as conn:
            # Lock rows and verify stock for each item before committing
            for item in items:
                row = conn.execute(
                    "SELECT stock_quantity FROM products WHERE id = ?",
                    (item['product_id'],)
                ).fetchone()
                if not row or row[0] < item['quantity']:
                    available = row[0] if row else 0
                    raise ValueError(f"Insufficient stock for product ID {item['product_id']}. Available: {available}, Requested: {item['quantity']}")

            conn.execute(
                """INSERT INTO orders (order_number, customer_id, payment_method, subtotal, tax, total, notes, status, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (order_number, customer_id, payment_method, subtotal, tax, total, notes, user_id)
            )
            order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            for item in items:
                conn.execute(
                    "INSERT INTO order_items (order_id, product_id, quantity, unit_price, total) VALUES (?, ?, ?, ?, ?)",
                    (order_id, item['product_id'], item['quantity'], item['price'], item['total'])
                )
                conn.execute(
                    "UPDATE products SET stock_quantity = stock_quantity - ? WHERE id = ? AND stock_quantity >= ?",
                    (item['quantity'], item['product_id'], item['quantity'])
                )
                # Log inventory transaction
                conn.execute(
                    "INSERT INTO inventory_transactions (product_id, transaction_type, quantity, reason) VALUES (?, 'sale', ?, ?)",
                    (item['product_id'], item['quantity'], f"Order {order_number}")
                )

            conn.execute(
                """INSERT INTO financial_transactions (transaction_type, category, amount, description, transaction_date, reference, order_id, created_by)
                   VALUES ('revenue', 'Sales', ?, ?, DATE('now'), ?, ?, ?)""",
                (total, f"Order {order_number}", order_number, order_id, user_id)
            )
            conn.execute(
                "UPDATE customers SET total_spent = total_spent + ? WHERE id = ?",
                (total, customer_id)
            )

        log_activity(user_id, "create_order", f"Created order {order_number}")
        return order_number
    except ValueError:
        raise
    except Exception as e:
        print(f"Add order error: {e}")
        raise

def get_orders(search=None, status=None):
    try:
        query = """SELECT o.id, o.order_number, c.name AS customer_name, o.order_date, o.status,
                          o.payment_method, o.payment_status, o.total
                   FROM orders o
                   LEFT JOIN customers c ON o.customer_id = c.id
                   WHERE 1=1"""
        params = []
        if search:
            query += " AND (o.order_number LIKE ? OR c.name LIKE ?)"
            params.extend([f'%{search}%', f'%{search}%'])
        if status and status != "All":
            query += " AND o.status = ?"
            params.append(status.lower())
        query += " ORDER BY o.order_date DESC"
        with get_db() as conn:
            df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as e:
        print(f"Get orders error: {e}")
        return pd.DataFrame()

def get_production_records():
    try:
        with get_db() as conn:
            df = pd.read_sql_query(
                """SELECT pr.id, p.name AS product_name, pr.batch_number, pr.shift, pr.operator,
                          pr.quantity, pr.produced_date, pr.status, pr.quality_score
                   FROM production_records pr
                   LEFT JOIN products p ON pr.product_id = p.id
                   ORDER BY pr.produced_date DESC""",
                conn
            )
        return df
    except Exception as e:
        print(f"Get production records error: {e}")
        return pd.DataFrame()

def add_production_record(product_id, batch_number, shift, operator, quantity, produced_date, quality_score, notes, user_id):
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO production_records (product_id, batch_number, shift, operator, quantity, produced_date, quality_score, notes, recorded_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (product_id, batch_number, shift, operator, float(quantity), str(produced_date), float(quality_score), notes, user_id)
            )
            conn.execute(
                "UPDATE products SET stock_quantity = stock_quantity + ? WHERE id = ?",
                (int(quantity), product_id)
            )
            conn.execute(
                "INSERT INTO inventory_transactions (product_id, transaction_type, quantity, reason) VALUES (?, 'production', ?, ?)",
                (product_id, int(quantity), f"Batch {batch_number}")
            )
        log_activity(user_id, "add_production", f"Added production batch {batch_number}")
        return True
    except Exception as e:
        print(f"Add production error: {e}")
        return False

def get_machines():
    try:
        with get_db() as conn:
            df = pd.read_sql_query("SELECT * FROM machines ORDER BY name", conn)
        return df
    except Exception:
        return pd.DataFrame()

def get_real_revenue(period='all'):
    try:
        if period == 'month':
            query = "SELECT COALESCE(SUM(total), 0) AS v FROM orders WHERE status != 'cancelled' AND strftime('%Y-%m', order_date) = strftime('%Y-%m', 'now')"
        elif period == 'year':
            query = "SELECT COALESCE(SUM(total), 0) AS v FROM orders WHERE status != 'cancelled' AND strftime('%Y', order_date) = strftime('%Y', 'now')"
        else:
            query = "SELECT COALESCE(SUM(total), 0) AS v FROM orders WHERE status != 'cancelled'"
        with get_db() as conn:
            row = conn.execute(query).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0

def get_real_expenses(period='all'):
    try:
        if period == 'month':
            query = "SELECT COALESCE(SUM(amount), 0) AS v FROM financial_transactions WHERE transaction_type = 'expense' AND strftime('%Y-%m', transaction_date) = strftime('%Y-%m', 'now')"
        elif period == 'year':
            query = "SELECT COALESCE(SUM(amount), 0) AS v FROM financial_transactions WHERE transaction_type = 'expense' AND strftime('%Y', transaction_date) = strftime('%Y', 'now')"
        else:
            query = "SELECT COALESCE(SUM(amount), 0) AS v FROM financial_transactions WHERE transaction_type = 'expense'"
        with get_db() as conn:
            row = conn.execute(query).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0

def get_profit_margin():
    total_rev = get_real_revenue('all')
    total_exp = get_real_expenses('all')
    net = total_rev - total_exp
    margin = (net / total_rev * 100) if total_rev > 0 else 0
    return total_rev, total_exp, net, margin

def get_revenue_by_product():
    try:
        with get_db() as conn:
            df = pd.read_sql_query(
                """SELECT p.category, SUM(oi.total) AS revenue
                   FROM order_items oi
                   JOIN products p ON oi.product_id = p.id
                   JOIN orders   o ON oi.order_id   = o.id
                   WHERE o.status != 'cancelled'
                   GROUP BY p.category""",
                conn
            )
        return df
    except Exception:
        return pd.DataFrame()

def get_monthly_financial_trend(months=6):
    try:
        months = max(1, min(int(months), 120))  # clamp to safe range
        with get_db() as conn:
            rev_df = pd.read_sql_query(
                """SELECT strftime('%Y-%m', order_date) AS month, SUM(total) AS revenue
                    FROM orders WHERE status != 'cancelled'
                    GROUP BY strftime('%Y-%m', order_date)
                    ORDER BY month DESC LIMIT ?""",
                conn, params=(months,)
            )
            exp_df = pd.read_sql_query(
                """SELECT strftime('%Y-%m', transaction_date) AS month, SUM(amount) AS expenses
                    FROM financial_transactions WHERE transaction_type = 'expense'
                    GROUP BY strftime('%Y-%m', transaction_date)
                    ORDER BY month DESC LIMIT ?""",
                conn, params=(months,)
            )
        if not rev_df.empty:
            result = rev_df.merge(exp_df, on='month', how='outer').fillna(0)
            return result.sort_values('month')
        return pd.DataFrame()
    except Exception:
        return pd.DataFrame()

def add_expense_transaction(category, amount, description, transaction_date, reference, user_id):
    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO financial_transactions (transaction_type, category, amount, description, transaction_date, reference, status, created_by)
                   VALUES ('expense', ?, ?, ?, ?, ?, 'completed', ?)""",
                (category, float(amount), description, str(transaction_date), reference, user_id)
            )
        log_activity(user_id, "add_expense", f"Added expense: {category} - ₵{amount}")
        return True
    except Exception as e:
        print(f"Add expense error: {e}")
        return False

def get_dashboard_metrics():
    try:
        with get_db() as conn:
            products_count  = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
            customers_count = conn.execute("SELECT COUNT(*) FROM customers WHERE status = 'active'").fetchone()[0]
            pending_orders  = conn.execute("SELECT COUNT(*) FROM orders WHERE status = 'pending'").fetchone()[0]
            low_stock       = conn.execute("SELECT COUNT(*) FROM products WHERE stock_quantity <= min_stock").fetchone()[0]
        monthly_revenue = get_real_revenue('month')
        return products_count, customers_count, pending_orders, monthly_revenue, low_stock
    except Exception:
        return 0, 0, 0, 0, 0

def export_dataframe_to_csv(df):
    """Returns a bytes buffer for download."""
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode('utf-8')

def export_dataframe_to_excel(df):
    """Returns bytes for Excel download."""
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    return buf.getvalue()


# ─────────────────────────────────────────────
# PAGES
# ─────────────────────────────────────────────
def show_login_page():
    company_name = get_system_setting('company_name') or 'NBN Enterprise'
    company_logo = get_system_setting('company_logo') or '🏭'
    primary_color = get_system_setting('primary_color') or '#b91c1c'
    login_bg = get_system_setting('login_background') or 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'

    st.markdown(f"""
    <style>
        .stApp {{ background: {login_bg}; }}
        .login-container {{
            max-width: 450px; margin: 0 auto; padding: 2rem;
            background: white; border-radius: 1rem;
            box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); margin-top: 8%;
        }}
        .login-header {{ text-align: center; margin-bottom: 2rem; }}
        .login-header h1 {{ color: {primary_color}; font-size: 2.5rem; margin-bottom: 0.5rem; }}
        .login-header p {{ color: #666; }}
        .stButton > button {{
            background-color: {primary_color}; color: white; width: 100%;
            border-radius: 0.5rem; padding: 0.5rem; font-weight: 600;
        }}
    </style>
    """, unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.markdown(
            f'<div class="login-header"><h1>{company_logo} {company_name}</h1><p>Enterprise Management System</p></div>',
            unsafe_allow_html=True
        )

        render_toast()

        # Show persistent login error (cleared after display)
        login_error = st.session_state.get('login_error')
        if login_error:
            st.error(login_error)
            st.session_state.login_error = None

        # Use st.form so widget values are preserved when the button is clicked
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("🔐 Login", use_container_width=True)

        if submitted:
            if not username or not password:
                st.session_state.login_error = "Please enter both username and password"
                st.rerun()
            elif is_rate_limited(username):
                st.session_state.login_error = (
                    f"Account temporarily locked due to too many failed attempts. "
                    f"Try again in {LOGIN_LOCKOUT_MINUTES} minutes."
                )
                st.rerun()
            else:
                user = login_user(username, password)
                if user:
                    clear_failed_attempts(username)
                    st.session_state.logged_in = True
                    st.session_state.user = user
                    st.session_state.page = 'main'
                    st.session_state.last_activity = datetime.now()
                    st.rerun()
                else:
                    record_failed_attempt(username)
                    attempts = st.session_state.login_attempts.get(username, [])
                    cutoff = datetime.now() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
                    recent_count = len([t for t in attempts if t > cutoff])
                    remaining = max(0, MAX_LOGIN_ATTEMPTS - recent_count)
                    st.session_state.login_error = f"Invalid username or password. {remaining} attempt(s) remaining."
                    st.rerun()

        st.markdown("---")
        st.markdown("<p style='text-align:center;font-size:0.8rem;color:#999;'>Demo: admin / admin123</p>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)





def show_dashboard():
    primary_color = get_system_setting('primary_color') or '#b91c1c'
    st.markdown(f"""
    <style>
        .metric-card {{ border-left: 4px solid {primary_color}; }}
        .metric-card:hover {{ box-shadow: 0 20px 25px -5px rgba(185,28,28,0.1); }}
    </style>
    """, unsafe_allow_html=True)

    st.title("📊 Dashboard")
    st.markdown(f"Welcome back, **{st.session_state.user['full_name']}**! 👋")
    render_toast()
    st.markdown("---")

    with st.spinner("Loading metrics..."):
        products_count, customers_count, pending_orders, monthly_revenue, low_stock = get_dashboard_metrics()

    col1, col2, col3, col4, col5 = st.columns(5)
    metrics = [
        (col1, "Products",        str(products_count),      "Total SKUs"),
        (col2, "Customers",       str(customers_count),     "Active accounts"),
        (col3, "Pending Orders",  str(pending_orders),      "Awaiting processing"),
        (col4, "Monthly Revenue", f"₵{monthly_revenue:,.0f}", "This month"),
        (col5, "Low Stock Alert", str(low_stock),           "Items below threshold"),
    ]
    for col, label, value, sub in metrics:
        with col:
            st.markdown(f"""
            <div class='metric-card'>
                <h3 style='margin:0;color:#666;'>{label}</h3>
                <h2 style='margin:0;color:{primary_color};'>{value}</h2>
                <small>{sub}</small>
            </div>""", unsafe_allow_html=True)

    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Inventory Distribution")
        try:
            with get_db() as conn:
                inv_data = pd.read_sql_query(
                    "SELECT category, SUM(stock_quantity) AS total FROM products GROUP BY category", conn
                )
            if not inv_data.empty:
                fig = px.pie(inv_data, values='total', names='category',
                             color_discrete_sequence=['#b91c1c', '#fbbf24', '#3b82f6', '#10b981'])
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        except Exception:
            st.info("Unable to load inventory chart.")

    with col2:
        st.subheader("📋 Recent Orders")
        if has_permission(st.session_state.user['id'], 'manage_orders'):
            orders_df = get_orders()
            if not orders_df.empty:
                st.dataframe(orders_df.head(5), use_container_width=True, hide_index=True)
            else:
                st.info("No recent orders")
        else:
            st.info("You don't have permission to view orders")

    st.subheader("📈 Production Trend (Last 7 Days)")
    try:
        with get_db() as conn:
            prod_data = pd.read_sql_query(
                """SELECT produced_date, SUM(quantity) AS total
                   FROM production_records
                   WHERE produced_date >= date('now', '-7 days')
                   GROUP BY produced_date ORDER BY produced_date""",
                conn
            )
        if not prod_data.empty:
            fig = px.line(prod_data, x='produced_date', y='total', markers=True, color_discrete_sequence=['#b91c1c'])
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No production data available for the last 7 days")
    except Exception:
        st.info("Unable to load production chart.")


def show_products():
    if not has_permission(st.session_state.user['id'], 'manage_products'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("📦 Product Management")
    st.info("💡 SKU is automatically generated based on product category")
    render_toast()

    tab1, tab2, tab3, tab4 = st.tabs(["📋 Product List", "➕ Add Product", "✏️ Edit/Delete", "📤 Export"])

    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            search = st.text_input("🔍 Search Products", placeholder="Search by name or SKU...")
        with col2:
            category_filter = st.selectbox("📁 Category", ["All Categories", "Tissue", "Roofing", "Accessory", "Raw Material"])

        with st.spinner("Loading products..."):
            products_df = get_products(search, category_filter)

        if not products_df.empty:
            # Pagination
            page_size = 20
            total_pages = max(1, -(-len(products_df) // page_size))
            page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
            start = (page_num - 1) * page_size
            st.caption(f"Showing {start+1}–{min(start+page_size, len(products_df))} of {len(products_df)} products")
            st.dataframe(products_df.iloc[start:start+page_size], use_container_width=True, hide_index=True)
        else:
            st.info("No products found")

    with tab2:
        with st.form("add_product_form", clear_on_submit=True):
            st.subheader("Add New Product")
            col1, col2 = st.columns(2)
            with col1:
                name = st.text_input("Product Name *")
                category = st.selectbox("Category *", ["Tissue", "Roofing", "Accessory", "Raw Material"])
                price = st.number_input("Price (₵) *", min_value=0.0, step=0.01)
            with col2:
                cost = st.number_input("Cost (₵)", min_value=0.0, step=0.01)
                stock = st.number_input("Initial Stock *", min_value=0, step=1)
                min_stock = st.number_input("Minimum Stock Alert *", min_value=0, step=1)
                unit = st.text_input("Unit *", value="units")
            description = st.text_area("Description")

            preview_sku = generate_sku(category)
            st.caption(f"📝 Auto-generated SKU will be: **{preview_sku}**")

            submitted = st.form_submit_button("✅ Add Product", use_container_width=True)
            if submitted:
                errors = []
                if not name.strip():
                    errors.append("Product name is required")
                if price < 0:
                    errors.append("Price cannot be negative")
                if cost < 0:
                    errors.append("Cost cannot be negative")
                if cost > price and price > 0:
                    errors.append("Cost should not exceed price")
                if errors:
                    for e in errors:
                        st.warning(e)
                else:
                    with st.spinner("Adding product..."):
                        success, sku = add_product(name, category, price, cost, stock, min_stock, unit, description, st.session_state.user['id'])
                    if success:
                        show_toast(f"Product added successfully! SKU: {sku}")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("Error adding product. Please try again.")

    with tab3:
        products_df = get_products()
        if not products_df.empty:
            product_options = {f"{row['name']} ({row['sku']})": row['id'] for _, row in products_df.iterrows()}
            selected = st.selectbox("Select Product to Edit/Delete", list(product_options.keys()))
            pid = product_options[selected]
            try:
                with get_db() as conn:
                    p_df = pd.read_sql_query("SELECT * FROM products WHERE id=?", conn, params=(pid,))
                p = p_df.iloc[0]

                col1, col2 = st.columns(2)
                with col1:
                    e_name  = st.text_input("Name", value=str(p['name']))
                    cats = ["Tissue", "Roofing", "Accessory", "Raw Material"]
                    e_cat   = st.selectbox("Category", cats, index=cats.index(p['category']) if p['category'] in cats else 0)
                    e_price = st.number_input("Price", value=float(p['price']), step=0.01)
                with col2:
                    e_cost  = st.number_input("Cost", value=float(p['cost']) if p['cost'] else 0.0, step=0.01)
                    e_stock = st.number_input("Stock", value=int(p['stock_quantity']), step=1)
                    e_min   = st.number_input("Min Stock", value=int(p['min_stock']), step=1)
                    e_unit  = st.text_input("Unit", value=str(p['unit']))
                e_desc = st.text_area("Description", value=str(p['description']) if p['description'] else "")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("💾 Update Product", use_container_width=True):
                        if not e_name.strip():
                            st.warning("Product name is required")
                        else:
                            with st.spinner("Updating..."):
                                ok = update_product(pid, e_name, e_cat, e_price, e_cost, e_stock, e_min, e_unit, e_desc, st.session_state.user['id'])
                            if ok:
                                show_toast("Product updated successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to update product.")
                with col2:
                    if st.button("🗑️ Delete Product", use_container_width=True, type="secondary"):
                        with st.spinner("Deleting..."):
                            ok = delete_product(pid, st.session_state.user['id'])
                        if ok:
                            show_toast("Product deleted successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to delete product.")
            except Exception as e:
                st.error(f"Error loading product: {e}")
        else:
            st.info("No products to edit")

    with tab4:
        st.subheader("Export Products")
        products_df = get_products()
        if not products_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                csv_data = export_dataframe_to_csv(products_df)
                st.download_button("⬇️ Download CSV", data=csv_data, file_name="products.csv", mime="text/csv", use_container_width=True)
            with col2:
                try:
                    xlsx_data = export_dataframe_to_excel(products_df)
                    st.download_button("⬇️ Download Excel", data=xlsx_data, file_name="products.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True)
                except Exception:
                    st.info("Excel export requires openpyxl. CSV export is available.")
        else:
            st.info("No products to export")


def show_inventory():
    if not has_permission(st.session_state.user['id'], 'manage_inventory'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("🏪 Inventory Management")
    render_toast()

    try:
        with get_db() as conn:
            total_value = conn.execute("SELECT COALESCE(SUM(stock_quantity * price), 0) FROM products").fetchone()[0]
            low_count   = conn.execute("SELECT COUNT(*) FROM products WHERE stock_quantity <= min_stock").fetchone()[0]
    except Exception:
        total_value, low_count = 0, 0

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("💰 Total Inventory Value", f"₵{total_value:,.0f}")
    with col2:
        st.metric("⚠️ Low Stock Alerts", low_count, delta="Needs attention" if low_count > 0 else None)
    with col3:
        st.metric("📦 Total Products", len(get_products()))

    st.markdown("---")
    st.subheader("📋 Current Inventory Levels")

    with st.spinner("Loading inventory..."):
        products_df = get_products()

    if not products_df.empty:
        products_df['status'] = products_df.apply(
            lambda x: '🔴 Low Stock' if x['stock_quantity'] <= x['min_stock'] else '🟢 In Stock', axis=1
        )
        st.dataframe(products_df, use_container_width=True, hide_index=True)

        low_stock_items = products_df[products_df['status'] == '🔴 Low Stock']
        if not low_stock_items.empty:
            st.warning(f"⚠️ {len(low_stock_items)} items are below minimum stock level. Please reorder soon!")

        st.markdown("---")
        st.subheader("📤 Export Inventory")
        col1, col2 = st.columns(2)
        with col1:
            st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(products_df),
                               file_name="inventory.csv", mime="text/csv", use_container_width=True)
        with col2:
            try:
                st.download_button("⬇️ Download Excel", data=export_dataframe_to_excel(products_df),
                                   file_name="inventory.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                   use_container_width=True)
            except Exception:
                pass


def show_customers():
    if not has_permission(st.session_state.user['id'], 'manage_customers'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("👥 Customer Management")
    st.info("💡 Customer Code is automatically generated")
    render_toast()

    tab1, tab2, tab3, tab4 = st.tabs(["📋 Customer List", "➕ Add Customer", "✏️ Edit/Delete", "📤 Export"])

    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            search = st.text_input("🔍 Search Customers", placeholder="Search by name, code, or email...")
        with col2:
            status_filter = st.selectbox("Status", ["All", "active", "inactive", "vip"])
        with st.spinner("Loading customers..."):
            customers_df = get_customers(search, status_filter)
        if not customers_df.empty:
            page_size = 20
            total_pages = max(1, -(-len(customers_df) // page_size))
            page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="cust_page")
            start = (page_num - 1) * page_size
            st.caption(f"Showing {start+1}–{min(start+page_size, len(customers_df))} of {len(customers_df)} customers")
            st.dataframe(customers_df.iloc[start:start+page_size], use_container_width=True, hide_index=True)
        else:
            st.info("No customers found")

    with tab2:
        with st.form("add_customer_form", clear_on_submit=True):
            st.subheader("Add New Customer")
            col1, col2 = st.columns(2)
            with col1:
                name  = st.text_input("Customer Name *")
                email = st.text_input("Email")
                phone = st.text_input("Phone")
            with col2:
                address = st.text_input("Address")
                city    = st.text_input("City")
                ctype   = st.selectbox("Customer Type", ["Contractor", "Distributor", "Retailer", "End User"])
                status  = st.selectbox("Status", ["active", "inactive", "vip"])

            preview_code = generate_customer_code()
            st.caption(f"📝 Auto-generated Customer Code will be: **{preview_code}**")

            if st.form_submit_button("✅ Add Customer", use_container_width=True):
                errors = []
                if not name.strip():
                    errors.append("Customer name is required")
                if email and not validate_email(email):
                    errors.append("Invalid email format")
                if phone and not validate_phone(phone):
                    errors.append("Invalid phone number format")
                if errors:
                    for e in errors:
                        st.warning(e)
                else:
                    with st.spinner("Adding customer..."):
                        success, code = add_customer(name, email, phone, address, city, ctype, status, st.session_state.user['id'])
                    if success:
                        show_toast(f"Customer added! Code: {code}")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("Error adding customer.")

    with tab3:
        customers_df = get_customers()
        if not customers_df.empty:
            cust_options = {f"{row['name']} ({row['customer_code']})": row['id'] for _, row in customers_df.iterrows()}
            selected = st.selectbox("Select Customer to Edit/Delete", list(cust_options.keys()))
            cid = cust_options[selected]
            try:
                with get_db() as conn:
                    c_df = pd.read_sql_query("SELECT * FROM customers WHERE id=?", conn, params=(cid,))
                c = c_df.iloc[0]
                col1, col2 = st.columns(2)
                with col1:
                    e_name  = st.text_input("Name", value=str(c['name']))
                    e_email = st.text_input("Email", value=str(c['email']) if c['email'] else "")
                    e_phone = st.text_input("Phone", value=str(c['phone']) if c['phone'] else "")
                with col2:
                    e_addr  = st.text_input("Address", value=str(c['address']) if c['address'] else "")
                    e_city  = st.text_input("City", value=str(c['city']) if c['city'] else "")
                    ctypes  = ["Contractor", "Distributor", "Retailer", "End User"]
                    e_type  = st.selectbox("Customer Type", ctypes, index=ctypes.index(c['customer_type']) if c['customer_type'] in ctypes else 0)
                    statuses = ["active", "inactive", "vip"]
                    e_status = st.selectbox("Status", statuses, index=statuses.index(c['status']) if c['status'] in statuses else 0)

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("💾 Update Customer", use_container_width=True):
                        errors = []
                        if not e_name.strip():
                            errors.append("Name is required")
                        if e_email and not validate_email(e_email):
                            errors.append("Invalid email format")
                        if e_phone and not validate_phone(e_phone):
                            errors.append("Invalid phone format")
                        if errors:
                            for e in errors:
                                st.warning(e)
                        else:
                            ok = update_customer(cid, e_name, e_email, e_phone, e_addr, e_city, e_type, e_status, st.session_state.user['id'])
                            if ok:
                                show_toast("Customer updated successfully!")
                                st.rerun()
                            else:
                                st.error("Failed to update customer.")
                with col2:
                    if st.button("🗑️ Delete Customer", use_container_width=True, type="secondary"):
                        ok = delete_customer(cid, st.session_state.user['id'])
                        if ok:
                            show_toast("Customer deleted successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to delete customer.")
            except Exception as e:
                st.error(f"Error loading customer: {e}")
        else:
            st.info("No customers to edit")

    with tab4:
        customers_df = get_customers()
        if not customers_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(customers_df),
                                   file_name="customers.csv", mime="text/csv", use_container_width=True)
            with col2:
                try:
                    st.download_button("⬇️ Download Excel", data=export_dataframe_to_excel(customers_df),
                                       file_name="customers.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True)
                except Exception:
                    pass


def show_orders():
    if not has_permission(st.session_state.user['id'], 'manage_orders'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("📋 Order Management")
    st.info("💡 Order Number is automatically generated")
    render_toast()

    tab1, tab2, tab3 = st.tabs(["📋 Orders List", "🛒 Create Order", "📤 Export"])

    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            search = st.text_input("🔍 Search Orders", placeholder="Search by order number or customer...")
        with col2:
            status_filter = st.selectbox("Status", ["All", "pending", "processing", "shipped", "completed", "cancelled"])
        with st.spinner("Loading orders..."):
            orders_df = get_orders(search, status_filter)
        if not orders_df.empty:
            page_size = 20
            total_pages = max(1, -(-len(orders_df) // page_size))
            page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="ord_page")
            start = (page_num - 1) * page_size
            st.caption(f"Showing {start+1}–{min(start+page_size, len(orders_df))} of {len(orders_df)} orders")
            st.dataframe(orders_df.iloc[start:start+page_size], use_container_width=True, hide_index=True)
        else:
            st.info("No orders found")

    with tab2:
        customers_df = get_customers()
        if not customers_df.empty:
            cust_options = {row['name']: row['id'] for _, row in customers_df.iterrows()}
            selected_cust = st.selectbox("Select Customer", list(cust_options.keys()))
            cust_id = cust_options[selected_cust]

            with st.spinner("Loading products..."):
                products_df = get_products()

            if not products_df.empty:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    prod_labels = [f"{row['name']} - ₵{row['price']} (Stock: {row['stock_quantity']})" for _, row in products_df.iterrows()]
                    prod_choice = st.selectbox("Product", prod_labels)
                with col2:
                    qty = st.number_input("Quantity", min_value=1, value=1, step=1)
                with col3:
                    if st.button("➕ Add to Cart", use_container_width=True):
                        idx = prod_labels.index(prod_choice)
                        prod = products_df.iloc[idx]
                        # Real-time stock validation
                        try:
                            with get_db() as conn:
                                live_stock = conn.execute("SELECT stock_quantity FROM products WHERE id=?", (int(prod['id']),)).fetchone()[0]
                        except Exception:
                            live_stock = prod['stock_quantity']
                        if qty <= live_stock:
                            st.session_state.order_items.append({
                                'product_id': int(prod['id']),
                                'name': prod['name'],
                                'quantity': int(qty),
                                'price': float(prod['price']),
                                'total': float(qty * prod['price'])
                            })
                            show_toast(f"Added {qty} x {prod['name']}")
                            st.rerun()
                        else:
                            st.error(f"❌ Only {live_stock} units available")

                if st.session_state.order_items:
                    st.markdown("---")
                    st.subheader("🛒 Shopping Cart")
                    items_df = pd.DataFrame(st.session_state.order_items)
                    st.dataframe(items_df[['name', 'quantity', 'price', 'total']], use_container_width=True, hide_index=True)

                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("🗑️ Clear Cart", use_container_width=True):
                            st.session_state.order_items = []
                            st.rerun()

                    subtotal = sum(i['total'] for i in st.session_state.order_items)
                    tax = subtotal * 0.125
                    total = subtotal + tax

                    st.markdown(f"""
                    <div style='background:#f0f0f0;padding:1rem;border-radius:0.5rem;margin:1rem 0;'>
                        <p><strong>Subtotal:</strong> ₵{subtotal:,.2f}</p>
                        <p><strong>Tax (12.5%):</strong> ₵{tax:,.2f}</p>
                        <p><strong>Total:</strong> <strong style='color:#b91c1c;font-size:1.2rem;'>₵{total:,.2f}</strong></p>
                    </div>
                    """, unsafe_allow_html=True)

                    preview_order = generate_order_number()
                    st.caption(f"📝 Order Number will be: **{preview_order}**")

                    payment = st.selectbox("Payment Method", ["Cash", "Mobile Money", "Bank Transfer", "Credit"])
                    notes   = st.text_area("Order Notes")

                    if st.button("✅ Place Order", type="primary", use_container_width=True):
                        try:
                            with st.spinner("Processing order..."):
                                order_num = add_order(cust_id, st.session_state.order_items, payment, notes, st.session_state.user['id'])
                            show_toast(f"Order {order_num} created successfully!")
                            st.balloons()
                            st.session_state.order_items = []
                            st.rerun()
                        except ValueError as ve:
                            st.error(f"❌ Stock error: {ve}")
                        except Exception as e:
                            st.error(f"❌ Failed to place order: {e}")
            else:
                st.warning("No products available. Please add products first.")
        else:
            st.warning("No customers available. Please add customers first.")

    with tab3:
        orders_df = get_orders()
        if not orders_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(orders_df),
                                   file_name="orders.csv", mime="text/csv", use_container_width=True)
            with col2:
                try:
                    st.download_button("⬇️ Download Excel", data=export_dataframe_to_excel(orders_df),
                                       file_name="orders.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True)
                except Exception:
                    pass
        else:
            st.info("No orders to export")


def show_production():
    if not has_permission(st.session_state.user['id'], 'manage_production'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("🏭 Production Management")
    render_toast()

    # Machine status panel — plain render (st.fragment requires Streamlit ≥1.37)
    machines_df = get_machines()
    header_col, meta_col = st.columns([3, 1])
    with header_col:
        st.subheader("🔧 Machine Status")
    with meta_col:
        st.caption(f"🔄 Last updated: {datetime.now().strftime('%H:%M:%S')}")

    if not machines_df.empty:
        status_colors = {"running": "#16a34a", "maintenance": "#d97706", "idle": "#6b7280"}
        status_icons  = {"running": "🟢",       "maintenance": "🟡",       "idle": "⚪"}
        cols = st.columns(4)
        for idx, (_, machine) in enumerate(machines_df.iterrows()):
            status = str(machine['status']).lower()
            icon   = status_icons.get(status, "⚪")
            color  = status_colors.get(status, "#6b7280")
            eff    = float(machine['efficiency'])
            batch  = machine['current_batch'] if machine['current_batch'] else "—"
            speed  = machine['speed']         if machine['speed']         else "—"
            with cols[idx % 4]:
                st.markdown(f"""
                <div style='background:white;padding:1rem;border-radius:0.5rem;
                            margin-bottom:0.5rem;border-left:4px solid {color};
                            box-shadow:0 1px 3px rgba(0,0,0,0.08);'>
                    <h4 style='margin:0 0 0.4rem 0;font-size:1rem;'>{icon} {machine['name']}</h4>
                    <span style='display:inline-block;padding:0.15rem 0.5rem;border-radius:999px;
                                 font-size:0.7rem;font-weight:600;background:{color}22;color:{color};
                                 margin-bottom:0.5rem;'>{status.upper()}</span><br>
                    <small><b>Efficiency:</b> {eff:.1f}%</small><br>
                    <div class='progress-bar' style='margin:0.3rem 0 0.4rem;'>
                        <div class='progress-fill' style='width:{eff}%;background:{color};'></div>
                    </div>
                    <small><b>Batch:</b> {batch}</small><br>
                    <small><b>Speed:</b> {speed}</small>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No machines found.")

    st.markdown("---")
    tab1, tab2, tab3 = st.tabs(["📋 Production Records", "➕ Record Production", "📤 Export"])

    with tab1:
        with st.spinner("Loading records..."):
            prod_df = get_production_records()
        if not prod_df.empty:
            page_size = 20
            total_pages = max(1, -(-len(prod_df) // page_size))
            page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="prod_page")
            start = (page_num - 1) * page_size
            st.dataframe(prod_df.iloc[start:start+page_size], use_container_width=True, hide_index=True)

            st.subheader("📊 Production Summary")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Production", f"{prod_df['quantity'].sum():,.1f} units")
            with col2:
                avg_q = prod_df['quality_score'].mean()
                st.metric("Avg Quality Score", f"{avg_q:.1f}%")
            with col3:
                day_shift = prod_df[prod_df['shift'] == 'Day']['quantity'].sum()
                st.metric("Day Shift Total", f"{day_shift:,.1f}")
            with col4:
                night_shift = prod_df[prod_df['shift'] == 'Night']['quantity'].sum()
                st.metric("Night Shift Total", f"{night_shift:,.1f}")
        else:
            st.info("No production records found")

    with tab2:
        products_df = get_products()
        if not products_df.empty:
            with st.form("record_production_form", clear_on_submit=True):
                st.subheader("Record New Production Batch")
                col1, col2 = st.columns(2)
                with col1:
                    product_options = {row['name']: row['id'] for _, row in products_df.iterrows()}
                    selected_product = st.selectbox("Product *", list(product_options.keys()))
                    prod_prefix = products_df[products_df['name'] == selected_product]['sku'].iloc[0].split('-')[0]
                    batch_number = st.text_input("Batch Number *", placeholder=f"e.g., {prod_prefix}-{datetime.now().strftime('%y%m%d')}-001")
                    shift    = st.selectbox("Shift *", ["Day", "Night"])
                    quantity = st.number_input("Quantity Produced *", min_value=0.0, step=0.1, format="%.1f")
                with col2:
                    operator      = st.selectbox("Operator *", ["John Mensah", "Kwame Asante", "Abena Osei", "Yaw Amponsah"])
                    produced_date = st.date_input("Production Date *", datetime.now())
                    quality_score = st.slider("Quality Score (%) *", 0, 100, 95)
                    notes         = st.text_area("Notes", placeholder="Add any additional notes...")

                if st.form_submit_button("✅ Record Production", use_container_width=True):
                    errors = []
                    if not batch_number.strip():
                        errors.append("Batch number is required")
                    if quantity <= 0:
                        errors.append("Quantity must be greater than zero")
                    if errors:
                        for e in errors:
                            st.warning(e)
                    else:
                        product_id = product_options[selected_product]
                        with st.spinner("Recording..."):
                            ok = add_production_record(product_id, batch_number, shift, operator, quantity, produced_date, quality_score, notes, st.session_state.user['id'])
                        if ok:
                            show_toast(f"Production batch {batch_number} recorded!")
                            st.balloons()
                            st.rerun()
                        else:
                            st.error("Failed to record production. Please try again.")
        else:
            st.error("❌ No products available! Please add products before recording production.")

    with tab3:
        prod_df = get_production_records()
        if not prod_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(prod_df),
                                   file_name="production.csv", mime="text/csv", use_container_width=True)
            with col2:
                try:
                    st.download_button("⬇️ Download Excel", data=export_dataframe_to_excel(prod_df),
                                       file_name="production.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True)
                except Exception:
                    pass


def show_financials():
    if not has_permission(st.session_state.user['id'], 'manage_financials'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("💰 Financial Management - Real-Time Analytics")
    render_toast()
    st.markdown("---")

    period = st.selectbox("Select Period", ["All Time", "This Month", "This Year"])
    period_key = "month" if period == "This Month" else "year" if period == "This Year" else "all"

    with st.spinner("Loading financial data..."):
        revenue  = get_real_revenue(period_key)
        expenses = get_real_expenses(period_key)

    col1, col2, col3, col4 = st.columns(4)
    profit = revenue - expenses
    margin = (profit / revenue * 100) if revenue > 0 else 0
    with col1:
        st.metric("📈 Total Revenue",  f"₵{revenue:,.2f}")
    with col2:
        st.metric("📉 Total Expenses", f"₵{expenses:,.2f}")
    with col3:
        st.metric("💎 Net Profit",     f"₵{profit:,.2f}")
    with col4:
        st.metric("📊 Profit Margin",  f"{margin:.1f}%")

    st.markdown("---")
    st.subheader("📋 Profit & Loss Statement")
    total_rev, total_exp, net_profit, net_margin = get_profit_margin()

    col1, col2 = st.columns(2)
    with col1:
        rev_by_cat = get_revenue_by_product()
        if not rev_by_cat.empty:
            fig = px.pie(rev_by_cat, values='revenue', names='category', title='Revenue by Category',
                         color_discrete_sequence=['#b91c1c', '#fbbf24', '#3b82f6'])
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.markdown(f"""
        <div style='background:white;padding:1rem;border-radius:0.5rem;box-shadow:0 1px 3px rgba(0,0,0,0.1);'>
            <table style='width:100%'>
                <tr><td><strong>Total Revenue</strong></td><td style='text-align:right'><strong>₵{total_rev:,.2f}</strong></td></tr>
                <tr><td>Cost of Goods Sold</td><td style='text-align:right'>₵{total_exp:,.2f}</td></tr>
                <tr><td><strong>Gross Profit</strong></td><td style='text-align:right'><strong>₵{total_rev - total_exp:,.2f}</strong></td></tr>
                <tr style='border-top:1px solid #ddd'><td><strong>Operating Expenses</strong></td><td style='text-align:right'>₵{total_exp:,.2f}</td></tr>
                <tr><td><strong>Net Profit</strong></td><td style='text-align:right'><strong style='color:#10b981'>₵{net_profit:,.2f}</strong></td></tr>
                <tr><td>Profit Margin</td><td style='text-align:right'>{net_margin:.1f}%</td></tr>
            </table>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader("📈 Monthly Financial Trend")
    monthly_trend = get_monthly_financial_trend(12)
    if not monthly_trend.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=monthly_trend['month'], y=monthly_trend['revenue'],  name='Revenue',  line=dict(color='#10b981', width=3)))
        fig.add_trace(go.Scatter(x=monthly_trend['month'], y=monthly_trend['expenses'], name='Expenses', line=dict(color='#b91c1c', width=3)))
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("➕ Record New Expense")
    with st.expander("Add Expense Transaction", expanded=False):
        with st.form("add_expense_form", clear_on_submit=True):
            col1, col2, col3 = st.columns(3)
            with col1:
                exp_category = st.selectbox("Category", ['Raw Materials', 'Labor', 'Transport', 'Utilities', 'Marketing', 'Maintenance', 'Rent', 'Other'])
                exp_amount   = st.number_input("Amount (₵)", min_value=0.01, step=0.01)
            with col2:
                exp_date = st.date_input("Date", datetime.now())
                exp_ref  = st.text_input("Reference #")
            with col3:
                exp_desc = st.text_area("Description")

            if st.form_submit_button("✅ Record Expense", use_container_width=True):
                if exp_amount <= 0:
                    st.warning("Amount must be greater than zero")
                else:
                    with st.spinner("Recording..."):
                        ok = add_expense_transaction(exp_category, exp_amount, exp_desc, exp_date, exp_ref, st.session_state.user['id'])
                    if ok:
                        show_toast("Expense recorded successfully!")
                        st.rerun()
                    else:
                        st.error("Failed to record expense.")

    # Export financials
    st.markdown("---")
    st.subheader("📤 Export Financial Transactions")
    try:
        with get_db() as conn:
            ft_df = pd.read_sql_query("SELECT * FROM financial_transactions ORDER BY transaction_date DESC", conn)
        if not ft_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(ft_df),
                                   file_name="financials.csv", mime="text/csv", use_container_width=True)
            with col2:
                try:
                    st.download_button("⬇️ Download Excel", data=export_dataframe_to_excel(ft_df),
                                       file_name="financials.xlsx",
                                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                       use_container_width=True)
                except Exception:
                    pass
    except Exception:
        pass


def show_reports():
    if not has_permission(st.session_state.user['id'], 'view_reports'):
        st.error("❌ You don't have permission to access this page")
        return

    st.title("📈 Reports & Analytics")
    render_toast()

    report_type = st.selectbox("Select Report", ["📊 Inventory Report", "📈 Sales Report", "🏭 Production Report"])

    if report_type == "📊 Inventory Report":
        st.subheader("Inventory Status Report")
        with st.spinner("Loading..."):
            products_df = get_products()
        if not products_df.empty:
            try:
                with get_db() as conn:
                    cat_value = pd.read_sql_query(
                        "SELECT category, SUM(stock_quantity * price) AS value FROM products GROUP BY category", conn
                    )
                col1, col2 = st.columns(2)
                with col1:
                    fig = px.bar(cat_value, x='category', y='value', title='Inventory Value by Category',
                                 color='category', color_discrete_sequence=['#b91c1c', '#fbbf24', '#3b82f6'])
                    st.plotly_chart(fig, use_container_width=True)
                with col2:
                    st.dataframe(products_df, use_container_width=True, hide_index=True)

                low_stock = products_df[products_df['stock_quantity'] <= products_df['min_stock']]
                if not low_stock.empty:
                    st.warning(f"⚠️ {len(low_stock)} items are below minimum stock level")
                    st.dataframe(low_stock[['name', 'sku', 'stock_quantity', 'min_stock']], use_container_width=True, hide_index=True)
            except Exception as e:
                st.error(f"Error loading report: {e}")

        st.subheader("📤 Export")
        products_df2 = get_products()
        if not products_df2.empty:
            st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(products_df2),
                               file_name="inventory_report.csv", mime="text/csv")

    elif report_type == "📈 Sales Report":
        st.subheader("Sales Performance Report")
        with st.spinner("Loading..."):
            orders_df = get_orders()
        if not orders_df.empty:
            orders_df['order_date'] = pd.to_datetime(orders_df['order_date'])
            orders_df['month'] = orders_df['order_date'].dt.strftime('%Y-%m')
            monthly = orders_df.groupby('month')['total'].sum().reset_index()

            fig = px.line(monthly, x='month', y='total', title='Sales Trend', markers=True,
                          color_discrete_sequence=['#b91c1c'])
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Order Status Distribution")
            status_counts = orders_df['status'].value_counts().reset_index()
            status_counts.columns = ['status', 'count']
            fig = px.bar(status_counts, x='status', y='count', title='Orders by Status',
                         color='status', color_discrete_sequence=['#10b981', '#fbbf24', '#b91c1c', '#3b82f6'])
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("All Orders")
            st.dataframe(orders_df, use_container_width=True, hide_index=True)

            st.subheader("📤 Export")
            st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(orders_df),
                               file_name="sales_report.csv", mime="text/csv")
        else:
            st.info("No sales data available")

    elif report_type == "🏭 Production Report":
        st.subheader("Production Report")
        with st.spinner("Loading..."):
            prod_df = get_production_records()
        if not prod_df.empty:
            by_product = prod_df.groupby('product_name')['quantity'].sum().reset_index()
            fig = px.bar(by_product, x='product_name', y='quantity', title='Production by Product',
                         color='product_name', color_discrete_sequence=['#b91c1c', '#fbbf24'])
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Quality Analysis")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Average Quality Score", f"{prod_df['quality_score'].mean():.1f}%")
            with col2:
                st.metric("Batches with 90%+ Quality", len(prod_df[prod_df['quality_score'] >= 90]))

            st.subheader("Production Records")
            st.dataframe(prod_df, use_container_width=True, hide_index=True)

            st.subheader("📤 Export")
            st.download_button("⬇️ Download CSV", data=export_dataframe_to_csv(prod_df),
                               file_name="production_report.csv", mime="text/csv")
        else:
            st.info("No production data available")


def show_user_management():
    if st.session_state.user['role'] != 'admin':
        st.error("❌ Only administrators can access this page")
        return

    st.title("👥 User Management")
    render_toast()

    tab1, tab2, tab3 = st.tabs(["📋 Users List", "➕ Add User", "📊 Activity Log"])

    with tab1:
        with st.spinner("Loading users..."):
            users_df = get_all_users()
        if not users_df.empty:
            st.dataframe(users_df, use_container_width=True, hide_index=True)

            st.subheader("User Actions")
            user_options = {f"{row['full_name']} ({row['username']}) - {row['role']}": row['id'] for _, row in users_df.iterrows()}
            selected_user = st.selectbox("Select User", list(user_options.keys()))
            uid = user_options[selected_user]
            user_data = users_df[users_df['id'] == uid].iloc[0]

            col1, col2, col3 = st.columns(3)
            with col1:
                new_password = st.text_input("New Password", type="password", key="reset_pass")
                if st.button("Reset Password", use_container_width=True):
                    if new_password:
                        pw_ok, pw_msg = validate_password(new_password)
                        if pw_ok:
                            if change_user_password(uid, new_password, st.session_state.user['id']):
                                show_toast(f"Password reset for {user_data['username']}")
                                st.rerun()
                            else:
                                st.error("Failed to reset password.")
                        else:
                            st.warning(pw_msg)
                    else:
                        st.warning("Please enter a new password")
            with col2:
                if user_data['role'] != 'admin':
                    if st.button("Delete User", use_container_width=True, type="secondary"):
                        if delete_user(uid, st.session_state.user['id']):
                            show_toast(f"User {user_data['username']} deleted")
                            st.rerun()
                        else:
                            st.error("Failed to delete user.")
            with col3:
                roles = ["admin", "manager", "financial", "production", "sales", "viewer"]
                new_role = st.selectbox("Change Role", roles, index=roles.index(user_data['role']) if user_data['role'] in roles else 0)
                new_status = st.checkbox("Active", value=user_data['is_active'] == 1)
                if st.button("Update Role/Status", use_container_width=True):
                    if update_user(uid, user_data['email'], user_data['full_name'], new_role, 1 if new_status else 0, st.session_state.user['id']):
                        show_toast(f"User {user_data['username']} updated!")
                        st.rerun()
                    else:
                        st.error("Failed to update user.")

    with tab2:
        with st.form("add_user_form", clear_on_submit=True):
            st.subheader("Create New User")
            col1, col2 = st.columns(2)
            with col1:
                username  = st.text_input("Username *")
                email     = st.text_input("Email *")
                full_name = st.text_input("Full Name *")
            with col2:
                role             = st.selectbox("Role *", ["admin", "manager", "financial", "production", "sales", "viewer"])
                password         = st.text_input("Password *", type="password")
                confirm_password = st.text_input("Confirm Password *", type="password")

            st.caption("Password requirements: 8+ characters, 1 uppercase, 1 number")

            if st.form_submit_button("➕ Add User", use_container_width=True):
                errors = []
                if not username.strip():
                    errors.append("Username is required")
                if not email.strip():
                    errors.append("Email is required")
                elif not validate_email(email):
                    errors.append("Invalid email format")
                if not full_name.strip():
                    errors.append("Full name is required")
                if not password:
                    errors.append("Password is required")
                elif password != confirm_password:
                    errors.append("Passwords do not match")
                else:
                    pw_ok, pw_msg = validate_password(password)
                    if not pw_ok:
                        errors.append(pw_msg)
                if errors:
                    for e in errors:
                        st.warning(e)
                else:
                    with st.spinner("Creating user..."):
                        success, _ = add_user(username, password, email, full_name, role, st.session_state.user['id'])
                    if success:
                        show_toast(f"User {username} created successfully!")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("Username already exists or an error occurred.")

    with tab3:
        st.subheader("User Activity Log")
        with st.spinner("Loading activity log..."):
            activity_df = get_user_activity_log(200)
        if not activity_df.empty:
            page_size = 50
            total_pages = max(1, -(-len(activity_df) // page_size))
            page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="act_page")
            start = (page_num - 1) * page_size
            st.caption(f"Showing {start+1}–{min(start+page_size, len(activity_df))} of {len(activity_df)} entries")
            st.dataframe(activity_df.iloc[start:start+page_size], use_container_width=True, hide_index=True)

            st.download_button("⬇️ Export Activity Log", data=export_dataframe_to_csv(activity_df),
                               file_name="activity_log.csv", mime="text/csv")
        else:
            st.info("No activity logs available")


def show_system_settings():
    if st.session_state.user['role'] != 'admin':
        st.error("❌ Only administrators can access this page")
        return

    st.title("⚙️ System Settings")
    render_toast()

    tab1, tab2, tab3 = st.tabs(["🏢 Branding", "🎨 Appearance", "💾 Backup & Restore"])

    with tab1:
        with st.form("branding_form"):
            st.subheader("Company Information")
            company_name = st.text_input("Company Name", value=get_system_setting('company_name') or 'NBN Enterprise')
            company_logo = st.text_input("Company Logo (Emoji or Text)", value=get_system_setting('company_logo') or '🏭')
            system_name  = st.text_input("System Name", value=get_system_setting('system_name') or 'NBN Enterprise Management System')

            st.markdown("---")
            st.subheader("Preview")
            st.markdown(f"""
            <div style='background:#f0f0f0;padding:1rem;border-radius:0.5rem;text-align:center;'>
                <span style='font-size:2rem;'>{company_logo}</span>
                <h3>{company_name}</h3>
                <small>{system_name}</small>
            </div>
            """, unsafe_allow_html=True)

            if st.form_submit_button("💾 Save Branding", use_container_width=True):
                if company_name.strip():
                    update_system_setting('company_name', company_name.strip())
                    update_system_setting('company_logo', company_logo)
                    update_system_setting('system_name', system_name.strip())
                    show_toast("Branding updated successfully!")
                    st.rerun()
                else:
                    st.warning("Company name cannot be empty")

    with tab2:
        with st.form("appearance_form"):
            st.subheader("Color Scheme")
            primary_color   = st.color_picker("Primary Color",   value=get_system_setting('primary_color')   or '#b91c1c')
            secondary_color = st.color_picker("Secondary Color", value=get_system_setting('secondary_color') or '#fbbf24')

            st.subheader("Login Page Background")
            current_bg = get_system_setting('login_background')
            bg_options = ["Gradient Purple", "Gradient Red", "Gradient Blue", "Solid White", "Solid Dark"]
            bg_map = {
                "Gradient Purple": "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                "Gradient Red":    "linear-gradient(135deg, #b91c1c 0%, #fbbf24 100%)",
                "Gradient Blue":   "linear-gradient(135deg, #1e3c72 0%, #2a5298 100%)",
                "Solid White":     "#ffffff",
                "Solid Dark":      "#1a1a2e"
            }
            default_bg = next((name for name, val in bg_map.items() if val == current_bg), "Gradient Purple")
            bg_choice = st.selectbox("Background Style", bg_options, index=bg_options.index(default_bg))

            st.markdown("---")
            st.markdown(f"""
            <div style='background:{primary_color};color:white;padding:1rem;border-radius:0.5rem;margin-top:1rem;'>
                <h3>Primary Color Preview</h3>
                <p>This is how your primary color looks</p>
                <button style='background:{secondary_color};color:#333;border:none;padding:0.5rem 1rem;border-radius:0.25rem;'>Secondary Button</button>
            </div>
            """, unsafe_allow_html=True)

            if st.form_submit_button("💾 Save Appearance", use_container_width=True):
                update_system_setting('primary_color',   primary_color)
                update_system_setting('secondary_color', secondary_color)
                update_system_setting('login_background', bg_map[bg_choice])
                show_toast("Appearance updated successfully!")
                st.rerun()

    with tab3:
        st.subheader("💾 Backup & Export")
        st.markdown(
            "Export the entire database in your target format. "
            "Use **SQLite** for a direct file copy, or **PostgreSQL / MySQL** "
            "to get a ready-to-import SQL script when migrating or scaling."
        )

        # ── Format picker ──────────────────────────────────────────────
        fmt_col, info_col = st.columns([1, 2])
        with fmt_col:
            fmt = st.radio(
                "Export format",
                options=["SQLite (.db)", "PostgreSQL (.sql)", "MySQL (.sql)"],
                index=0,
                help="SQLite gives you a binary copy of the DB file. "
                     "PostgreSQL and MySQL generate a full SQL dump with "
                     "translated DDL + data inserts ready to run on the target server."
            )

        with info_col:
            if fmt == "SQLite (.db)":
                st.info(
                    "📦 **Binary file copy** — identical to the live database.\n\n"
                    "Restore by simply replacing the `.db` file on the server. "
                    "Best for quick backups and disaster recovery on the same stack."
                )
            elif fmt == "PostgreSQL (.sql)":
                st.info(
                    "🐘 **PostgreSQL SQL dump** — schema translated to PG syntax "
                    "(INTEGER → INTEGER, REAL → DOUBLE PRECISION, BOOLEAN, etc.) "
                    "with `GENERATED ALWAYS AS IDENTITY` for auto-increment columns.\n\n"
                    "Run with: `psql -U <user> -d <dbname> -f backup.sql`"
                )
            else:
                st.info(
                    "🐬 **MySQL SQL dump** — schema translated to MySQL syntax "
                    "(INT, DOUBLE, LONGTEXT, DATETIME, TINYINT(1)) with "
                    "`AUTO_INCREMENT` and `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`.\n\n"
                    "Run with: `mysql -u <user> -p <dbname> < backup.sql`"
                )

        st.markdown("---")

        # ── Tables included preview ─────────────────────────────────────
        with st.expander("📋 Tables included in export", expanded=False):
            tcols = st.columns(3)
            for i, tname in enumerate(_ALL_TABLES):
                tcols[i % 3].markdown(f"✅ `{tname}`")

        st.markdown("")

        # ── Export button ───────────────────────────────────────────────
        if st.button("⬇️ Generate & Download Backup", use_container_width=True, type="primary"):
            uid = st.session_state.user['id']
            ts  = datetime.now().strftime("%Y%m%d_%H%M%S")

            if fmt == "SQLite (.db)":
                with st.spinner("Packaging SQLite backup…"):
                    data, fname, err = export_backup_sqlite_file()
                if err:
                    st.error(f"❌ {err}")
                else:
                    log_activity(uid, "backup_export", f"SQLite binary export {fname}")
                    st.success(f"✅ SQLite backup ready — **{fname}**")
                    st.download_button(
                        label="💾 Download .db file",
                        data=data,
                        file_name=fname,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

            elif fmt == "PostgreSQL (.sql)":
                with st.spinner("Generating PostgreSQL dump…"):
                    sql, err = export_backup_sql('postgresql')
                if err:
                    st.error(f"❌ {err}")
                else:
                    fname = f"nbn_enterprise_postgresql_{ts}.sql"
                    log_activity(uid, "backup_export", f"PostgreSQL SQL export {fname}")
                    st.success(f"✅ PostgreSQL dump ready — **{fname}**")
                    st.download_button(
                        label="💾 Download PostgreSQL .sql",
                        data=sql.encode('utf-8'),
                        file_name=fname,
                        mime="text/plain",
                        use_container_width=True,
                    )

            else:  # MySQL
                with st.spinner("Generating MySQL dump…"):
                    sql, err = export_backup_sql('mysql')
                if err:
                    st.error(f"❌ {err}")
                else:
                    fname = f"nbn_enterprise_mysql_{ts}.sql"
                    log_activity(uid, "backup_export", f"MySQL SQL export {fname}")
                    st.success(f"✅ MySQL dump ready — **{fname}**")
                    st.download_button(
                        label="💾 Download MySQL .sql",
                        data=sql.encode('utf-8'),
                        file_name=fname,
                        mime="text/plain",
                        use_container_width=True,
                    )


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    init_database()
    check_session_timeout()

    if st.session_state.page == 'login':
        show_login_page()

    elif st.session_state.page == 'main' and st.session_state.logged_in:
        company_name  = get_system_setting('company_name')  or 'NBN Enterprise'
        primary_color = get_system_setting('primary_color') or '#b91c1c'

        with st.sidebar:
            st.markdown(f"""
            <div style='text-align:center;padding:1rem;background:{primary_color};border-radius:0.5rem;margin-bottom:1rem;'>
                <div style='color:white;'>
                    <h3>{company_name}</h3>
                    <small>{st.session_state.user['full_name']}</small><br>
                    <small style='opacity:0.8'>{st.session_state.user['role'].upper()}</small>
                </div>
            </div>
            """, unsafe_allow_html=True)

            menu_options, menu_icons = [], []
            perm_map = [
                ('view_dashboard',    "Dashboard",       "house"),
                ('manage_products',   "Products",        "box"),
                ('manage_inventory',  "Inventory",       "archive"),
                ('manage_customers',  "Customers",       "people"),
                ('manage_orders',     "Orders",          "cart"),
                ('manage_production', "Production",      "gear"),
                ('manage_financials', "Financials",      "coin"),
                ('view_reports',      "Reports",         "graph-up"),
            ]
            for perm, label, icon in perm_map:
                if has_permission(st.session_state.user['id'], perm):
                    menu_options.append(label)
                    menu_icons.append(icon)

            if st.session_state.user['role'] == 'admin':
                menu_options += ["User Management", "Settings"]
                menu_icons   += ["people-fill", "gear-fill"]

            menu_options.append("Logout")
            menu_icons.append("box-arrow-right")

            selected = option_menu(
                menu_title=None,
                options=menu_options,
                icons=menu_icons,
                default_index=0,
                styles={
                    "container":        {"padding": "0!important", "background-color": "#fafafa"},
                    "icon":             {"color": primary_color, "font-size": "1.2rem"},
                    "nav-link":         {"font-size": "0.9rem", "text-align": "left", "margin": "0.2rem 0"},
                    "nav-link-selected":{"background-color": primary_color},
                }
            )

            # Session timeout display
            if st.session_state.last_activity:
                elapsed = (datetime.now() - st.session_state.last_activity).total_seconds()
                remaining_mins = max(0, SESSION_TIMEOUT_MINUTES - int(elapsed / 60))
                st.markdown(f"<small style='color:#999;'>Session expires in {remaining_mins}m</small>", unsafe_allow_html=True)

            if selected == "Logout":
                log_activity(st.session_state.user['id'], "logout", f"User {st.session_state.user['username']} logged out")
                st.session_state.logged_in  = False
                st.session_state.user       = None
                st.session_state.page       = 'login'
                st.session_state.order_items = []
                st.session_state.last_activity = None
                st.rerun()

        page_map = {
            "Dashboard":       show_dashboard,
            "Products":        show_products,
            "Inventory":       show_inventory,
            "Customers":       show_customers,
            "Orders":          show_orders,
            "Production":      show_production,
            "Financials":      show_financials,
            "Reports":         show_reports,
            "User Management": show_user_management,
            "Settings":        show_system_settings,
        }
        if selected in page_map:
            page_map[selected]()

    else:
        # Invalid state — redirect to login
        st.session_state.page = 'login'
        st.session_state.logged_in = False
        st.rerun()


if __name__ == "__main__":
    main()