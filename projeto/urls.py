from django.contrib import admin
from django.urls import path
from app.views import port_scanner  # Importa a função do arquivo views.py que está no app

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', port_scanner, name='port_scanner'),
]