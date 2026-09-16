import os
import sys
import webbrowser
import time
import uvicorn
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "backend"))

if __name__ == "__main__":
    print("=" * 65)
    print("  🚀 GvulStand - Sistema de Gestão de Vulnerabilidades")
    print("  🔒 Governança ISO 27000 / ISO 9000 & Nessus CSV Parser")
    print("=" * 65)
    print("  Credenciais Padrão Iniciais:")
    print("  Usuário: Admin")
    print("  Senha:   Admin")
    print("-" * 65)
    print("  Iniciando servidor web em http://localhost:8000 ...")
    print("=" * 65)
    
    # Auto open browser after small delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://localhost:8000")
        
    import threading
    threading.Thread(target=open_browser, daemon=True).start()
    
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True, app_dir=str(BASE_DIR / "backend"))
