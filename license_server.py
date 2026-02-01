"""
Сервер лицензий для Twitch Bot
FastAPI + SQLite + PASETO v4
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3
import secrets
import hashlib
from typing import Optional
import pyseto
from pyseto import Key

app = FastAPI(title="License Server", version="1.0.0")

# CORS для доступа из приложения
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== КОНФИГУРАЦИЯ =====
DATABASE = "/data/licenses.db"  # Persistent storage in Railway volume
ADMIN_PASSWORD = "your_admin_password_here"  # СМЕНИ ЭТО!

# Секретный ключ для PASETO (генерируется один раз)
SECRET_KEY = Key.new(version=4, purpose="local", key=b"your-32-byte-secret-key-here!")  # СМЕНИ ЭТО!

# ===== МОДЕЛИ =====
class License(BaseModel):
    username: str
    plan: str
    days: int

class LicenseUpdate(BaseModel):
    key: str
    days: Optional[int] = None
    active: Optional[bool] = None

class ValidateRequest(BaseModel):
    key: str

# ===== БАЗА ДАННЫХ =====
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            plan TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            active BOOLEAN DEFAULT 1,
            last_check TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ===== ГЕНЕРАЦИЯ КЛЮЧЕЙ =====
def generate_paseto_token(username: str, plan: str, expires_at: datetime) -> str:
    """Генерирует PASETO v4 токен"""
    token = pyseto.encode(
        SECRET_KEY,
        payload={
            "sub": username,
            "plan": plan,
            "exp": expires_at.isoformat(),
            "iat": datetime.utcnow().isoformat(),
        },
        footer=b"license-v1"
    )
    return token.decode('utf-8')

def verify_paseto_token(token: str) -> dict:
    """Проверяет PASETO v4 токен"""
    try:
        decoded = pyseto.decode(SECRET_KEY, token, footer=b"license-v1")
        return decoded.payload
    except Exception as e:
        raise ValueError(f"Invalid token: {e}")

# ===== API ENDPOINTS =====

@app.get("/")
async def root():
    return {"status": "ok", "service": "License Server", "version": "1.0.0"}

@app.post("/api/validate")
async def validate_license(request: ValidateRequest):
    """
    Проверяет лицензионный ключ
    Вызывается клиентом каждый раз при входе
    """
    try:
        # Декодируем PASETO токен
        payload = verify_paseto_token(request.key)
        
        username = payload.get("sub")
        plan = payload.get("plan")
        expires_str = payload.get("exp")
        
        # Проверяем в БД
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT active, expires_at FROM licenses WHERE key = ?", (request.key,))
        result = c.fetchone()
        
        if not result:
            # Первая проверка - добавляем в БД
            expires_at = datetime.fromisoformat(expires_str)
            c.execute(
                "INSERT INTO licenses (key, username, plan, expires_at, last_check) VALUES (?, ?, ?, ?, ?)",
                (request.key, username, plan, expires_at, datetime.utcnow())
            )
            conn.commit()
            active = True
        else:
            active, expires_db = result
            expires_at = datetime.fromisoformat(expires_db)
            
            # Обновляем время последней проверки
            c.execute("UPDATE licenses SET last_check = ? WHERE key = ?", (datetime.utcnow(), request.key))
            conn.commit()
        
        conn.close()
        
        # Проверяем активность
        if not active:
            return {
                "valid": False,
                "error": "Лицензия деактивирована администратором"
            }
        
        # Проверяем срок
        if datetime.utcnow() > expires_at:
            return {
                "valid": False,
                "error": "Срок действия лицензии истёк"
            }
        
        days_remaining = (expires_at - datetime.utcnow()).days
        
        return {
            "valid": True,
            "username": username,
            "plan": plan,
            "days_remaining": days_remaining,
            "expires_at": expires_at.strftime("%Y-%m-%d")
        }
        
    except Exception as e:
        return {
            "valid": False,
            "error": "Неверный ключ лицензии"
        }

# ===== АДМИН ПАНЕЛЬ =====

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """Админ-панель для управления лицензиями"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Админ панель - Лицензии</title>
        <meta charset="UTF-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: Arial, sans-serif;
                background: #1a1a1a;
                color: #fff;
                padding: 20px;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { margin-bottom: 30px; color: #FFD700; }
            
            .section {
                background: rgba(40, 40, 40, 0.95);
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            
            input, select {
                padding: 10px;
                background: rgba(60, 60, 60, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 5px;
                color: #fff;
                margin-right: 10px;
                margin-bottom: 10px;
            }
            
            button {
                padding: 10px 20px;
                background: #FFD700;
                border: none;
                border-radius: 5px;
                color: #1a1a1a;
                font-weight: bold;
                cursor: pointer;
            }
            
            button:hover { background: #FFA500; }
            
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            th { background: rgba(60, 60, 60, 0.8); }
            
            .active { color: #4CAF50; }
            .inactive { color: #ff6b6b; }
            
            .key-display {
                background: rgba(0, 0, 0, 0.3);
                padding: 15px;
                border-radius: 5px;
                margin-top: 15px;
                word-break: break-all;
            }
            
            .btn-deactivate { background: #ff6b6b; color: #fff; }
            .btn-extend { background: #4CAF50; color: #fff; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Админ панель - Управление лицензиями</h1>
            
            <div class="section">
                <h2>➕ Создать новую лицензию</h2>
                <form id="createForm">
                    <input type="text" id="username" placeholder="Имя пользователя" required>
                    <select id="plan">
                        <option value="Basic">Basic</option>
                        <option value="Pro" selected>Pro</option>
                        <option value="Premium">Premium</option>
                    </select>
                    <input type="number" id="days" placeholder="Дней" value="30" required>
                    <button type="submit">Создать ключ</button>
                </form>
                <div id="newKey" class="key-display" style="display:none;"></div>
            </div>
            
            <div class="section">
                <h2>📋 Все лицензии</h2>
                <button onclick="loadLicenses()">🔄 Обновить список</button>
                <table id="licensesTable">
                    <thead>
                        <tr>
                            <th>Пользователь</th>
                            <th>План</th>
                            <th>Создан</th>
                            <th>Истекает</th>
                            <th>Осталось дней</th>
                            <th>Статус</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody id="licensesBody"></tbody>
                </table>
            </div>
        </div>
        
        <script>
            // API URL
            const API_URL = window.location.origin;
            
            // Создание лицензии
            document.getElementById('createForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const plan = document.getElementById('plan').value;
                const days = parseInt(document.getElementById('days').value);
                
                const response = await fetch(`${API_URL}/admin/create`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, plan, days })
                });
                
                const data = await response.json();
                
                if (data.key) {
                    document.getElementById('newKey').style.display = 'block';
                    document.getElementById('newKey').innerHTML = `
                        <strong>✅ Ключ создан!</strong><br><br>
                        <strong>Ключ:</strong><br>
                        <code>${data.key}</code><br><br>
                        <strong>Пользователь:</strong> ${username}<br>
                        <strong>План:</strong> ${plan}<br>
                        <strong>Действует до:</strong> ${data.expires_at}
                    `;
                    
                    // Очистка формы
                    document.getElementById('username').value = '';
                    
                    // Обновление списка
                    setTimeout(() => loadLicenses(), 1000);
                }
            });
            
            // Загрузка списка лицензий
            async function loadLicenses() {
                const response = await fetch(`${API_URL}/admin/list`);
                const data = await response.json();
                
                const tbody = document.getElementById('licensesBody');
                tbody.innerHTML = '';
                
                data.licenses.forEach(license => {
                    const row = tbody.insertRow();
                    const expires = new Date(license.expires_at);
                    const daysLeft = Math.floor((expires - new Date()) / (1000 * 60 * 60 * 24));
                    
                    row.innerHTML = `
                        <td>${license.username}</td>
                        <td>${license.plan}</td>
                        <td>${new Date(license.created_at).toLocaleDateString()}</td>
                        <td>${expires.toLocaleDateString()}</td>
                        <td>${daysLeft > 0 ? daysLeft : '0'}</td>
                        <td class="${license.active ? 'active' : 'inactive'}">
                            ${license.active ? '✅ Активна' : '❌ Отключена'}
                        </td>
                        <td>
                            ${license.active 
                                ? `<button class="btn-deactivate" onclick="toggleLicense('${license.key}', false)">Отключить</button>`
                                : `<button class="btn-extend" onclick="toggleLicense('${license.key}', true)">Включить</button>`
                            }
                            <button class="btn-extend" onclick="extendLicense('${license.key}')">Продлить +30д</button>
                        </td>
                    `;
                });
            }
            
            // Отключение/включение лицензии
            async function toggleLicense(key, active) {
                await fetch(`${API_URL}/admin/update`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, active })
                });
                loadLicenses();
            }
            
            // Продление лицензии
            async function extendLicense(key) {
                await fetch(`${API_URL}/admin/update`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key, days: 30 })
                });
                loadLicenses();
            }
            
            // Загрузка при открытии страницы
            loadLicenses();
        </script>
    </body>
    </html>
    """

@app.post("/admin/create")
async def admin_create_license(license: License):
    """Создание новой лицензии"""
    try:
        # Генерируем ключ
        expires_at = datetime.utcnow() + timedelta(days=license.days)
        key = generate_paseto_token(license.username, license.plan, expires_at)
        
        # Сохраняем в БД
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO licenses (key, username, plan, expires_at) VALUES (?, ?, ?, ?)",
            (key, license.username, license.plan, expires_at)
        )
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "key": key,
            "username": license.username,
            "plan": license.plan,
            "expires_at": expires_at.strftime("%Y-%m-%d")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/list")
async def admin_list_licenses():
    """Список всех лицензий"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT key, username, plan, created_at, expires_at, active FROM licenses ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    
    licenses = []
    for row in rows:
        licenses.append({
            "key": row[0],
            "username": row[1],
            "plan": row[2],
            "created_at": row[3],
            "expires_at": row[4],
            "active": bool(row[5])
        })
    
    return {"licenses": licenses}

@app.post("/admin/update")
async def admin_update_license(update: LicenseUpdate):
    """Обновление лицензии (продление, деактивация)"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Обновление активности
    if update.active is not None:
        c.execute("UPDATE licenses SET active = ? WHERE key = ?", (update.active, update.key))
    
    # Продление
    if update.days is not None:
        c.execute("SELECT expires_at FROM licenses WHERE key = ?", (update.key,))
        result = c.fetchone()
        if result:
            current_expires = datetime.fromisoformat(result[0])
            new_expires = current_expires + timedelta(days=update.days)
            c.execute("UPDATE licenses SET expires_at = ? WHERE key = ?", (new_expires, update.key))
    
    conn.commit()
    conn.close()
    
    return {"success": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)