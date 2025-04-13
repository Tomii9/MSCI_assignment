FROM python:3.11
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ip_tool.py .
RUN chmod +x ip_tool.py
ENTRYPOINT ["python", "./ip_tool.py"]