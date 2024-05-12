FROM python:3.11.4-slim-buster

WORKDIR /apartment

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y netcat

RUN pip install --upgrade pip

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY ./entrypoint.sh .
RUN sed -i 's/\r$//g' /apartment/entrypoint.sh
RUN chmod +x /apartment/entrypoint.sh

COPY . .

ENTRYPOINT ["/apartment/entrypoint.sh"]