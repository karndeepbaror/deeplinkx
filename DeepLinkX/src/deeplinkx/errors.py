class DeeplinkXError(Exception):
    pass


class ApkError(DeeplinkXError):
    pass


class ManifestError(ApkError):
    pass


class ProfileError(DeeplinkXError):
    pass


class RuleError(DeeplinkXError):
    pass


class DynamicError(DeeplinkXError):
    pass


class SafetyError(DynamicError):
    pass
