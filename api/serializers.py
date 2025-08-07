# api/serializers.py
from rest_framework import serializers

class URLSerializer(serializers.Serializer):
    """
    Accepts a URL as a simple string. The logic layer will handle
    adding a scheme if it's missing.
    """
    url = serializers.CharField(required=True, trim_whitespace=True)