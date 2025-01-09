init:
	python -m venv venv
	venv/bin/python -m pip install -r requirements.txt

install:
	venv/bin/python -m pip install . --force-reinstall
	
test:
	venv/bin/python -m pytest -v

init-steve-db:
	mariadb -u steve --password=changeme -P 3306 --skip-ssl < steve-config.sql