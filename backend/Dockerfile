FROM python:3.12

RUN apt-get update && apt-get install -y netcat-traditional
WORKDIR /app
COPY tools/requirements.txt .
RUN pip install -r requirements.txt

COPY tools/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

CMD [ "python", "manage.py", "runserver", "0.0.0.0:8001" ]
ENTRYPOINT [ "/usr/local/bin/docker-entrypoint.sh" ]