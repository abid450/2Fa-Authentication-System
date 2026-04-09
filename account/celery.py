import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
# আপনার প্রোজেক্টের নাম 'chat' হওয়ায় 'project.settings' না লিখে 'chat.settings' লিখতে হবে
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'chat.settings')

app = Celery('chat')  # 'project' না লিখে 'chat' লিখুন

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')