@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

set "MAVEN_VERSION=3.9.9"
set "BASE_DIR=%~dp0"
if "%BASE_DIR:~-1%"=="\" set "BASE_DIR=%BASE_DIR:~0,-1%"
set "WRAPPER_DIR=%BASE_DIR%\.mvn\wrapper"
set "ARCHIVE=%WRAPPER_DIR%\apache-maven-%MAVEN_VERSION%-bin.zip"
set "MAVEN_HOME=%WRAPPER_DIR%\apache-maven-%MAVEN_VERSION%"
set "MAVEN_CMD=%MAVEN_HOME%\bin\mvn.cmd"
set "DOWNLOAD_URL=https://archive.apache.org/dist/maven/maven-3/%MAVEN_VERSION%/binaries/apache-maven-%MAVEN_VERSION%-bin.zip"

if not exist "%MAVEN_CMD%" (
  if not exist "%WRAPPER_DIR%" mkdir "%WRAPPER_DIR%"

  if not exist "%ARCHIVE%" (
    echo Downloading Maven %MAVEN_VERSION%...
    powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%ARCHIVE%'"
    if errorlevel 1 (
      echo Failed to download Maven from %DOWNLOAD_URL%
      exit /b 1
    )
  )

  echo Extracting Maven %MAVEN_VERSION%...
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ARCHIVE%' -DestinationPath '%WRAPPER_DIR%' -Force"
  if errorlevel 1 (
    echo Failed to extract Maven archive %ARCHIVE%
    exit /b 1
  )
)

call "%MAVEN_CMD%" %*
exit /b %ERRORLEVEL%