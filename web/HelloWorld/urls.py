from django.conf.urls import url
from . import search
 
urlpatterns = [
    url(r'^index$', search.index),
    url(r'^result$', search.result)
]

