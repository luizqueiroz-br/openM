"""Cobertura do ApiKey.to_dict() — branch secure=True (issue #61)."""
from openm.extensions import db
from openm.models.api_key import ApiKey


class TestApiKeyToDict:
    """Cobertura dos dois branches de ``ApiKey.to_dict(secure=...)``.

    - ``secure=False`` (default): retorna ``masked_key``, NÃO expõe
      ``key_value`` em plain text. Usado na API pública.
    - ``secure=True``: retorna ``key_value`` em plain text. Usado
      internamente (ex.: pelo HunterService.get_key()).
    """

    def test_to_dict_secure_true_exposes_key_value(self, app):
        """``secure=True`` expõe ``key_value`` em plain text (uso interno)."""
        with app.app_context():
            key = ApiKey(
                service_name="test-service",
                key_value="my-secret-api-key-123",
                key_type="paid",
                is_active=True,
            )
            db.session.add(key)
            db.session.commit()

            data = key.to_dict(secure=True)

        assert data["key_value"] == "my-secret-api-key-123"
        assert "masked_key" not in data

    def test_to_dict_secure_false_returns_masked_key(self, app):
        """``secure=False`` (default) retorna ``masked_key``, NÃO ``key_value``."""
        with app.app_context():
            key = ApiKey(
                service_name="test-service",
                key_value="my-secret-api-key-123",
                key_type="paid",
                is_active=True,
            )
            db.session.add(key)
            db.session.commit()

            data = key.to_dict()  # default secure=False

        # my-secret-api-key-123 → "my-s" + "****" + "-123" = "my-s****-123"
        assert data["masked_key"] == "my-s****-123"
        assert "key_value" not in data

    def test_masked_key_short_returns_placeholder(self, app):
        """Chaves curtas (≤8 chars) usam placeholder ``****`` ao invés de fatiar."""
        with app.app_context():
            key = ApiKey(
                service_name="test-service",
                key_value="abc123",  # 6 chars
                key_type="free",
                is_active=True,
            )
            db.session.add(key)
            db.session.commit()

            data = key.to_dict()

        # Branch defensivo: se a chave for muito curta pra mostrar 4 prefixo +
        # 4 sufixo, mostra apenas "****" (não vaza info).
        assert data["masked_key"] == "****"
        assert "key_value" not in data
