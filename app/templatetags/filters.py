from django.template.defaulttags import register
import logging

logger = logging.getLogger('app')

@register.filter
def lookup(dictionary, key):
    if key in dictionary.keys():
        return dictionary[key]

@register.simple_tag
def active(request, pattern):
    try:
        import re
        if re.search(pattern, request.path):
            return 'active'
    except Exception as e:
        logger.error(e)
    return ''