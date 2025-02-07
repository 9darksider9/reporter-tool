@echo off

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install requirements
echo Installing requirements...
pip install -e .

REM Initialize the database
echo Initializing database...
flask db upgrade

REM Run the application
echo Starting the application...
flask run 