from eve.render import JSONRenderer

class HALRenderer(JSONRenderer):
    mime = ("application/hal+json",)
