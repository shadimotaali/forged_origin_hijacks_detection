"""Login page (PeeringDB only)."""

import reflex as rx
from backend.oauth import AuthState
from components.navbar import navbar


@rx.page(route="/login")
def login() -> rx.Component:
    return rx.fragment(
        navbar(),
        rx.center(
            rx.vstack(
                rx.heading("Sign in", size="6", mb="4"),
                rx.text(
                    "Use your PeeringDB account to sign in.",
                    size="4",
                    color=rx.color_mode_cond(light="slate.600", dark="slate.300"),
                    mb="6",
                ),
                rx.button(
                    rx.hstack(
                        rx.image(src="/pdb-logo-coloured.png", width="160px", height="auto"),
                    ),
                    size="4",
                    variant="solid",
                    on_click=AuthState.oauth2_authorize_peeringdb,
                    style={"border_radius": "12px"},
                ),
                spacing="6",
                align="center",
                justify="center",
                width="100%",
                max_width="400px",
            ),
            width="100%",
            min_height="100vh",
            background=rx.color_mode_cond(light="#f9fafb", dark="#18181b"),
            display="flex",
            justify_content="center",
            align_items="center",
        )
    )
