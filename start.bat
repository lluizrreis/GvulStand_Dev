@echo off
title GvulStand - Gerenciador de Vulnerabilidades
cls
echo ====================================================================
echo   GvulStand - Sistema de Gestao de Vulnerabilidades (ISO 27000/9000)
echo ====================================================================
echo.
echo Escolha o modo de execucao:
echo [1] Execucao Local Instantanea (Python + SQLite - Recomendado)
echo [2] Execucao em Containers Docker (MariaDB 11.4 + Web App)
echo [3] Executar Testes Automatizados (Pytest)
echo [4] Sair
echo.
set /p opt="Digite a opcao desejada [1-4]: "

if "%opt%"=="1" (
    echo.
    echo Iniciando GvulStand em modo local...
    python run_local.py
    pause
    exit /b
)

if "%opt%"=="2" (
    echo.
    echo Iniciando containers com Docker Compose...
    docker compose up --build -d
    echo.
    echo Containers inicializados com sucesso!
    echo Acesse o sistema em: http://localhost:8000
    echo Credenciais Iniciais: Admin / Admin
    echo.
    pause
    exit /b
)

if "%opt%"=="3" (
    echo.
    echo Executando suite de testes automatizados...
    set PYTHONPATH=%cd%\backend
    python -m pytest backend/tests -v
    pause
    exit /b
)

exit /b
