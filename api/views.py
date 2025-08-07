from django.shortcuts import render

# Create your views here.
# api/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import URLSerializer
from predictor.predictor_logic import predict_url_class

class PredictURLView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = URLSerializer(data=request.data)
        if serializer.is_valid():
            url_to_check = serializer.validated_data['url']
            result = predict_url_class(url_to_check)
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)