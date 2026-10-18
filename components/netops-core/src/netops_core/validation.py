class ValidationError(Exception):
    def __init__(self, message="", *, field=None, code=None, diagnostic=None):
        super().__init__(message)
        self.diagnostic = diagnostic if diagnostic is not None else ((field, code) if field and code else None)
