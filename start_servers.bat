@echo off
echo Starting NetScan AI Servers...
echo.

echo [1/3] Starting ML API Server on port 5000...
start "ML API" cmd /k "cd Nmap_AI\ml_api && python app.py"

timeout /t 3 /nobreak >nul

echo [2/3] Starting Node.js Backend on port 3001...
start "Node Backend" cmd /k "cd Nmap_AI\backend && npm start"

timeout /t 3 /nobreak >nul

echo [3/3] Starting React Frontend on port 3000...
start "React Frontend" cmd /k "cd Nmap_AI\frontend\NMAP_AI_Scanner && npm run dev"

echo.
echo All servers are starting!
echo.
echo ML API:       http://localhost:5000
echo Node Backend: http://localhost:3001
echo React App:    http://localhost:3000
echo.
echo Press any key to close this window (servers will keep running)...
pause >nul
