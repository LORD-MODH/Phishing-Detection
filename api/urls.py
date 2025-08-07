# api/urls.py
from django.urls import path
from .views import PredictURLView

urlpatterns = [
    path('predict/', PredictURLView.as_view(), name='predict-url'),
]