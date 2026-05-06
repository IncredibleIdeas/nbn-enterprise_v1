# helpers.py - Database helper functions with full error handling and security
import sqlite3
import pandas as pd
import shutil
import os
from datetime import datetime
from contextlib import contextmanager


DB_PATH = 'nbn_enterprise.db'
BACKUP_DIR = 'backups'


@contextmanager
def get_db_connection():
    """Context manager for database connections - prevents leaks."""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def backup_database():
    """Create a backup of the database with error handling."""
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        if not os.path.exists(DB_PATH):
            return "Error: Database file not found."

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f'nbn_enterprise_backup_{timestamp}.db')
        shutil.copy2(DB_PATH, backup_path)
        return f"Backup created at {backup_path}"
    except PermissionError as e:
        return f"Error: Permission denied - {e}"
    except Exception as e:
        return f"Error creating backup: {e}"


def get_low_stock_report():
    """Get report of items below minimum stock level."""
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query(
                """
                SELECT sku, name, category, stock_quantity, min_stock,
                       (min_stock - stock_quantity) AS needed_quantity
                FROM products
                WHERE stock_quantity <= min_stock
                ORDER BY CAST(stock_quantity AS REAL) / NULLIF(min_stock, 0) ASC
                """,
                conn
            )
        return df
    except Exception as e:
        print(f"Error fetching low stock report: {e}")
        return pd.DataFrame()


def get_monthly_performance(year=None, month=None):
    """Get monthly performance metrics with parameterized queries."""
    if not year:
        year = datetime.now().year
    if not month:
        month = datetime.now().month

    year_str = str(int(year))
    month_str = f"{int(month):02d}"

    try:
        with get_db_connection() as conn:
            revenue_row = pd.read_sql_query(
                """
                SELECT COALESCE(SUM(amount), 0) AS total
                FROM financial_transactions
                WHERE transaction_type = 'revenue'
                  AND strftime('%Y', transaction_date) = ?
                  AND strftime('%m', transaction_date) = ?
                """,
                conn,
                params=(year_str, month_str)
            )
            revenue = revenue_row['total'].iloc[0]

            expenses_row = pd.read_sql_query(
                """
                SELECT COALESCE(SUM(amount), 0) AS total
                FROM financial_transactions
                WHERE transaction_type = 'expense'
                  AND strftime('%Y', transaction_date) = ?
                  AND strftime('%m', transaction_date) = ?
                """,
                conn,
                params=(year_str, month_str)
            )
            expenses = expenses_row['total'].iloc[0]

            orders_row = pd.read_sql_query(
                """
                SELECT COALESCE(COUNT(*), 0) AS count
                FROM orders
                WHERE strftime('%Y', order_date) = ?
                  AND strftime('%m', order_date) = ?
                """,
                conn,
                params=(year_str, month_str)
            )
            orders = orders_row['count'].iloc[0]

        return {
            'revenue': revenue,
            'expenses': expenses,
            'profit': revenue - expenses,
            'orders': orders,
            'margin': ((revenue - expenses) / revenue * 100) if revenue > 0 else 0
        }
    except Exception as e:
        print(f"Error fetching monthly performance: {e}")
        return {'revenue': 0, 'expenses': 0, 'profit': 0, 'orders': 0, 'margin': 0}


def get_product_sales_ranking(limit=10):
    """Get top selling products with input validation."""
    try:
        limit = max(1, min(int(limit), 200))  # clamp between 1 and 200
        with get_db_connection() as conn:
            df = pd.read_sql_query(
                """
                SELECT p.name, p.sku,
                       SUM(oi.quantity)  AS total_quantity_sold,
                       SUM(oi.total)     AS total_revenue
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                JOIN orders   o ON oi.order_id   = o.id
                WHERE o.status != 'cancelled'
                GROUP BY p.id, p.name, p.sku
                ORDER BY total_revenue DESC
                LIMIT ?
                """,
                conn,
                params=(limit,)
            )
        return df
    except Exception as e:
        print(f"Error fetching product sales ranking: {e}")
        return pd.DataFrame()


def get_customer_lifetime_value():
    """Calculate customer lifetime value metrics."""
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query(
                """
                SELECT c.name, c.customer_code, c.customer_type,
                       COUNT(o.id)                                          AS total_orders,
                       COALESCE(SUM(o.total), 0)                           AS total_spent,
                       COALESCE(AVG(o.total), 0)                           AS avg_order_value,
                       CAST(julianday('now') - julianday(MAX(o.order_date))
                            AS INTEGER)                                     AS days_since_last_order
                FROM customers c
                LEFT JOIN orders o ON c.id = o.customer_id
                GROUP BY c.id, c.name, c.customer_code, c.customer_type
                ORDER BY total_spent DESC
                """,
                conn
            )
        return df
    except Exception as e:
        print(f"Error fetching customer lifetime value: {e}")
        return pd.DataFrame()


def get_inventory_turnover_rate():
    """Calculate inventory turnover rate."""
    try:
        with get_db_connection() as conn:
            avg_inv_row = pd.read_sql_query(
                "SELECT COALESCE(AVG(stock_quantity * price), 0) AS avg_value FROM products",
                conn
            )
            avg_inventory = avg_inv_row['avg_value'].iloc[0]

            cogs_row = pd.read_sql_query(
                """
                SELECT COALESCE(SUM(oi.quantity * p.cost), 0) AS cogs
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                JOIN orders   o ON oi.order_id   = o.id
                WHERE o.status != 'cancelled'
                  AND strftime('%Y', o.order_date) = strftime('%Y', 'now')
                """,
                conn
            )
            cogs = cogs_row['cogs'].iloc[0]

        turnover = cogs / avg_inventory if avg_inventory > 0 else 0
        return round(turnover, 4)
    except Exception as e:
        print(f"Error calculating inventory turnover: {e}")
        return 0.0


def export_to_csv(table_name, filename):
    """
    Export a table to CSV.
    Only whitelisted table names are accepted to prevent SQL injection.
    """
    ALLOWED_TABLES = {
        'products', 'customers', 'orders', 'order_items',
        'financial_transactions', 'raw_materials',
        'machines', 'users', 'user_activity'
    }
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Table '{table_name}' is not allowed for export.")

    try:
        with get_db_connection() as conn:
            # Table name is validated above against a whitelist – safe to interpolate
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)  # noqa: S608

        df.to_csv(filename, index=False)
        return filename
    except Exception as e:
        print(f"Error exporting table '{table_name}' to CSV: {e}")
        raise