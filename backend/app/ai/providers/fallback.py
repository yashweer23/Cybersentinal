from app.ai.providers.base import ProviderResult


class FallbackAnalyst:
    def is_configured(self):
        return True

    def generate(self, catalog):
        return ProviderResult(
            plan=catalog.default_plan(), mode="FALLBACK", provider="deterministic"
        )
