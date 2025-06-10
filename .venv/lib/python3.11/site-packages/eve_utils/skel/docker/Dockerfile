FROM python:3.9-slim

ENV ES_API_PORT=80
EXPOSE 80

WORKDIR app
COPY {$project_name}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY {$project_name} .

CMD ["python", "run.py"]
