FROM python:3

WORKDIR /home/app

#If we add the requirements and install dependencies first, docker can use cache if requirements don't change
COPY requirements.txt /home/app
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py /home/app/
COPY static/ /home/app/static/
COPY Frontend/ /home/app/Frontend/

EXPOSE 3000

CMD ["python", "server.py"]

