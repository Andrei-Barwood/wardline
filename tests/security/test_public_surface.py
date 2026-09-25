from wardline.api.app import create_app


def test_public_surface():
    app = create_app()
    public_routes = set()
    for route in app.routes:
        if hasattr(route, "path"):
            public_routes.add(route.path)

    assert "/docs" not in public_routes
    assert "/redoc" not in public_routes
    assert "/openapi.json" not in public_routes
